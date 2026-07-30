from __future__ import annotations

import copy
import json
import unittest

from ctf_os.contracts.managed_rejection_v1 import (
    MANAGED_REJECTION_V1_ARTIFACT_CODES,
    MANAGED_REJECTION_V1_CONTRACT_CODES,
    MANAGED_REJECTION_V1_MAX_ATTEMPT,
    MANAGED_REJECTION_V1_MAX_DOCUMENT_BYTES,
    MANAGED_REJECTION_V1_MAX_ISSUES,
    MANAGED_REJECTION_V1_NORMALIZATION_CODES,
    ManagedRejectionV1ContractError,
    build_managed_rejection_v1,
    managed_artifact_publication_rejection_v1,
    managed_rejection_v1_canonical_json_bytes,
    project_reported_artifact_normalization_error_v1,
    validate_managed_rejection_v1_mapping,
)


class ManagedRejectionV1Tests(unittest.TestCase):
    def test_known_empty_command_error_becomes_typed_pointer(self) -> None:
        result = build_managed_rejection_v1(
            role="specialist",
            attempt=2,
            contract_errors=(
                "$.actions[3].command: command action requires text",
            ),
        )

        self.assertEqual(
            result,
            {
                "attempt": 2,
                "authority": "ctfos_engine",
                "issues": [
                    {
                        "code": "required_text_missing",
                        "kind": "role_output",
                        "pointer": "/actions/3/command",
                    }
                ],
                "omitted_count": 0,
                "role": "specialist",
                "schema_version": 1,
            },
        )
        self.assertEqual(
            validate_managed_rejection_v1_mapping(result),
            result,
        )

    def test_messages_values_and_unknown_paths_never_survive(self) -> None:
        secret = "FLAG{must-not-enter-next-context}"
        result = build_managed_rejection_v1(
            role="builder",
            attempt=1,
            contract_errors=(
                f"$.hypotheses[0].id: duplicate id {secret!r}",
                f"$.{secret}: expected string",
                f"{secret}",
                "$: invalid JSON: line 1 contains private payload",
            ),
        )
        encoded = managed_rejection_v1_canonical_json_bytes(result)

        self.assertNotIn(secret.encode(), encoded)
        self.assertNotIn(b"private payload", encoded)
        self.assertEqual(
            result["issues"],
            [
                {
                    "code": "contract_invalid",
                    "kind": "role_output",
                    "pointer": "",
                },
                {
                    "code": "invalid_json",
                    "kind": "role_output",
                    "pointer": "",
                },
                {
                    "code": "invalid_identifier",
                    "kind": "role_output",
                    "pointer": "/hypotheses/0/id",
                },
            ],
        )
        self.assertEqual(result["omitted_count"], 1)

    def test_projection_is_deterministic_deduplicated_and_capped(self) -> None:
        errors = [
            f"$.actions[{index}].command: command action requires text"
            for index in range(MANAGED_REJECTION_V1_MAX_ISSUES + 5)
        ]
        forward = build_managed_rejection_v1(
            role="builder",
            attempt=1,
            contract_errors=errors,
        )
        reverse = build_managed_rejection_v1(
            role="builder",
            attempt=1,
            contract_errors=list(reversed(errors)),
        )

        self.assertEqual(forward, reverse)
        self.assertEqual(
            len(forward["issues"]),
            MANAGED_REJECTION_V1_MAX_ISSUES,
        )
        self.assertEqual(forward["omitted_count"], 5)
        self.assertEqual(
            forward["issues"],
            sorted(
                forward["issues"],
                key=lambda item: (
                    item["pointer"],
                    item["code"],
                ),
            ),
        )
        self.assertLessEqual(
            len(managed_rejection_v1_canonical_json_bytes(forward)),
            MANAGED_REJECTION_V1_MAX_DOCUMENT_BYTES,
        )

    def test_artifact_rejection_has_ordinal_and_no_path_channel(self) -> None:
        artifact_issue = managed_artifact_publication_rejection_v1(
            proposal_ordinal=3,
            code="artifact_source_unopenable",
        )
        result = build_managed_rejection_v1(
            role="builder",
            attempt=1,
            artifact_publication_rejections=(artifact_issue,),
        )

        self.assertEqual(
            result["issues"],
            [
                {
                    "code": "artifact_source_unopenable",
                    "kind": "artifact_publication",
                    "proposal_ordinal": 3,
                }
            ],
        )
        self.assertNotIn("path", json.dumps(result, sort_keys=True))

        with self.assertRaises(ManagedRejectionV1ContractError):
            build_managed_rejection_v1(
                role="builder",
                attempt=1,
                artifact_publication_rejections=(
                    {
                        **artifact_issue,
                        "path": "artifacts/private/FLAG{secret}",
                    },
                ),
            )

    def test_known_run_wave_artifact_error_keeps_only_pointer_and_code(
        self,
    ) -> None:
        secret_path = "artifacts/workspace/FLAG{private}.tar.gz"
        raw_error = (
            f"cannot snapshot reported artifact {secret_path}: "
            "snapshot source cannot be opened safely"
        )
        issue = project_reported_artifact_normalization_error_v1(
            normalization_error=raw_error,
            artifact_ordinal=0,
        )
        result = build_managed_rejection_v1(
            role="builder",
            attempt=1,
            reported_artifact_rejections=(issue,),
        )
        encoded = managed_rejection_v1_canonical_json_bytes(result)

        self.assertEqual(
            result["issues"],
            [
                {
                    "code": "reported_artifact_unavailable",
                    "kind": "reported_artifact",
                    "pointer": "/artifacts/0/path",
                }
            ],
        )
        self.assertNotIn(secret_path.encode(), encoded)
        self.assertNotIn(b"opened safely", encoded)

        generic = project_reported_artifact_normalization_error_v1(
            normalization_error="arbitrary FLAG{private} exception",
            artifact_ordinal=1,
        )
        self.assertEqual(
            generic,
            {
                "code": "artifact_normalization_invalid",
                "kind": "reported_artifact",
                "pointer": "/artifacts/1/path",
            },
        )

    def test_closed_code_sets_are_enforced(self) -> None:
        self.assertIn("required_text_missing", MANAGED_REJECTION_V1_CONTRACT_CODES)
        self.assertIn(
            "artifact_source_unopenable",
            MANAGED_REJECTION_V1_ARTIFACT_CODES,
        )
        self.assertEqual(
            MANAGED_REJECTION_V1_NORMALIZATION_CODES,
            {
                "artifact_normalization_invalid",
                "reported_artifact_unavailable",
            },
        )
        with self.assertRaises(ManagedRejectionV1ContractError):
            managed_artifact_publication_rejection_v1(
                proposal_ordinal=1,
                code="raw_exception_text",
            )

        result = build_managed_rejection_v1(
            role="recon",
            attempt=1,
            contract_errors=("unknown free-form validator detail",),
        )
        self.assertEqual(
            result["issues"][0]["code"],
            "contract_invalid",
        )

    def test_malformed_builder_inputs_fail_closed(self) -> None:
        invalid_calls = (
            {
                "role": "unknown",
                "attempt": 1,
                "contract_errors": ("$: expected object",),
            },
            {
                "role": "builder",
                "attempt": True,
                "contract_errors": ("$: expected object",),
            },
            {
                "role": "builder",
                "attempt": MANAGED_REJECTION_V1_MAX_ATTEMPT + 1,
                "contract_errors": ("$: expected object",),
            },
            {
                "role": "builder",
                "attempt": 1,
                "contract_errors": "$: expected object",
            },
            {
                "role": "builder",
                "attempt": 1,
                "contract_errors": ({"message": "secret"},),
            },
            {
                "role": "builder",
                "attempt": 1,
                "contract_errors": (),
            },
        )
        for kwargs in invalid_calls:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ManagedRejectionV1ContractError):
                    build_managed_rejection_v1(**kwargs)

    def test_validator_rejects_noncanonical_or_covert_fields(self) -> None:
        valid = build_managed_rejection_v1(
            role="builder",
            attempt=1,
            contract_errors=(
                "$.actions[3].command: command action requires text",
                "$.status: invalid status",
            ),
        )
        mutations = []

        extra = copy.deepcopy(valid)
        extra["message"] = "FLAG{secret}"
        mutations.append(extra)

        unknown_pointer = copy.deepcopy(valid)
        unknown_pointer["issues"][0]["pointer"] = "/FLAG_secret"
        mutations.append(unknown_pointer)

        unknown_code = copy.deepcopy(valid)
        unknown_code["issues"][0]["code"] = "FLAG_secret"
        mutations.append(unknown_code)

        covert_reported_path = build_managed_rejection_v1(
            role="builder",
            attempt=1,
            reported_artifact_rejections=(
                project_reported_artifact_normalization_error_v1(
                    normalization_error=(
                        "cannot snapshot reported artifact x: missing"
                    ),
                    artifact_ordinal=0,
                ),
            ),
        )
        covert_reported_path["issues"][0]["path"] = "FLAG{secret}"
        mutations.append(covert_reported_path)

        wrong_authority = copy.deepcopy(valid)
        wrong_authority["authority"] = "model"
        mutations.append(wrong_authority)

        unsorted = copy.deepcopy(valid)
        unsorted["issues"].reverse()
        mutations.append(unsorted)

        duplicate = copy.deepcopy(valid)
        duplicate["issues"].append(copy.deepcopy(duplicate["issues"][0]))
        mutations.append(duplicate)

        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(ManagedRejectionV1ContractError):
                    validate_managed_rejection_v1_mapping(mutation)

    def test_validator_returns_fresh_canonical_mapping(self) -> None:
        original = build_managed_rejection_v1(
            role="captain",
            attempt=1,
            contract_errors=(
                "$.decision: captain with ok status must choose a next stage",
            ),
        )
        validated = validate_managed_rejection_v1_mapping(original)

        self.assertEqual(validated, original)
        self.assertIsNot(validated, original)
        self.assertIsNot(validated["issues"], original["issues"])
        parsed = json.loads(
            managed_rejection_v1_canonical_json_bytes(validated)
        )
        self.assertEqual(parsed, original)


if __name__ == "__main__":
    unittest.main()
