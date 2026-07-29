from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path

from ctf_os.engine.partial_oracle import (
    PartialOracleVerdict,
    REV_INVENTORY_CONTRACT_FINGERPRINT,
    REV_INVENTORY_CONTRACT_ID,
    REV_INVENTORY_CONTRACT_VERSION,
    REV_INVENTORY_MAX_BYTES,
    REV_INVENTORY_SCHEMA_VERSION,
    evaluate_rev_inventory,
)


SOURCE_BYTES = b"\x7fELFpartial-oracle-fixture"
SOURCE_SHA256 = hashlib.sha256(SOURCE_BYTES).hexdigest()
SOURCE_SIZE = len(SOURCE_BYTES)


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")


def valid_document() -> dict[str, object]:
    return {
        "binary": {
            "arch": "x86",
            "bits": 64,
            "bintype": "elf",
            "endian": "little",
            "havecode": True,
        },
        "contract": {
            "fingerprint": REV_INVENTORY_CONTRACT_FINGERPRINT,
            "id": REV_INVENTORY_CONTRACT_ID,
            "version": REV_INVENTORY_CONTRACT_VERSION,
        },
        "schema_version": REV_INVENTORY_SCHEMA_VERSION,
        "source": {
            "sha256": SOURCE_SHA256,
            "size_bytes": SOURCE_SIZE,
        },
        "status": "ok",
    }


def evaluate(document: dict[str, object]):
    return evaluate_rev_inventory(
        canonical_bytes(document),
        expected_source_sha256=SOURCE_SHA256,
        expected_source_size_bytes=SOURCE_SIZE,
    )


class RevPartialOracleTests(unittest.TestCase):
    def test_valid_inventory_confirms_neutral_binary_profile(self) -> None:
        first = evaluate(valid_document())
        second = evaluate(valid_document())

        self.assertEqual(first, second)
        self.assertEqual(first.verdict, PartialOracleVerdict.CONFIRMED)
        self.assertEqual(first.reason_code, "binary_profile_observed")
        self.assertEqual(first.source_sha256, SOURCE_SHA256)
        self.assertEqual(first.source_size_bytes, SOURCE_SIZE)
        self.assertIsNotNone(first.profile)
        assert first.profile is not None
        self.assertEqual(first.profile.arch, "x86")
        self.assertEqual(first.profile.bits, 64)
        self.assertEqual(first.profile.bintype, "elf")
        self.assertEqual(first.profile.endian, "little")
        self.assertTrue(first.profile.havecode)

    def test_producer_and_parser_contract_fingerprints_match(self) -> None:
        repository = Path(__file__).resolve().parent.parent
        template_dir = repository / "ctf-os-image" / "templates" / "rev"
        module_name = "_ctfos_rev_inventory_contract_test"
        spec = importlib.util.spec_from_file_location(
            module_name,
            template_dir / "inventory.py",
        )
        self.assertIsNotNone(spec)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        sys.path.insert(0, str(template_dir))
        try:
            spec.loader.exec_module(module)
        finally:
            sys.path.remove(str(template_dir))
            sys.modules.pop(module_name, None)

        self.assertEqual(
            module.CONTRACT_FINGERPRINT,
            REV_INVENTORY_CONTRACT_FINGERPRINT,
        )
        self.assertEqual(module.CONTRACT_ID, REV_INVENTORY_CONTRACT_ID)
        self.assertEqual(
            module.CONTRACT_VERSION,
            REV_INVENTORY_CONTRACT_VERSION,
        )

    def test_duplicate_keys_are_rejected_at_every_object_level(self) -> None:
        payload = canonical_bytes(valid_document()).decode("ascii")
        mutations = {
            "top": payload.replace(
                '"status":"ok"}',
                '"status":"ok","status":"ok"}',
            ),
            "contract": payload.replace(
                f'"id":"{REV_INVENTORY_CONTRACT_ID}"',
                (
                    f'"id":"{REV_INVENTORY_CONTRACT_ID}",'
                    f'"id":"{REV_INVENTORY_CONTRACT_ID}"'
                ),
            ),
            "source": payload.replace(
                f'"sha256":"{SOURCE_SHA256}"',
                f'"sha256":"{SOURCE_SHA256}","sha256":"{SOURCE_SHA256}"',
            ),
            "binary": payload.replace(
                '"bits":64',
                '"bits":64,"bits":64',
            ),
        }
        for name, mutated in mutations.items():
            with self.subTest(name=name):
                result = evaluate_rev_inventory(
                    mutated.encode("ascii"),
                    expected_source_sha256=SOURCE_SHA256,
                    expected_source_size_bytes=SOURCE_SIZE,
                )
                self.assertEqual(
                    result.verdict,
                    PartialOracleVerdict.ERROR,
                )
                self.assertEqual(result.reason_code, "duplicate_json_key")

    def test_boolean_values_are_never_accepted_as_integers(self) -> None:
        mutations = []
        for path in (
            ("schema_version",),
            ("contract", "version"),
            ("source", "size_bytes"),
            ("binary", "bits"),
        ):
            document = valid_document()
            target = document
            for component in path[:-1]:
                value = target[component]
                assert isinstance(value, dict)
                target = value
            target[path[-1]] = True
            mutations.append((path, document))

        for path, document in mutations:
            with self.subTest(path=path):
                result = evaluate(document)
                self.assertEqual(
                    result.verdict,
                    PartialOracleVerdict.ERROR,
                )
                self.assertEqual(result.reason_code, "invalid_schema")

    def test_source_hash_and_size_must_match_canonical_inventory(self) -> None:
        wrong_hash = copy.deepcopy(valid_document())
        source = wrong_hash["source"]
        assert isinstance(source, dict)
        source["sha256"] = "0" * 64
        hash_result = evaluate(wrong_hash)
        self.assertEqual(hash_result.verdict, PartialOracleVerdict.ERROR)
        self.assertEqual(hash_result.reason_code, "source_hash_mismatch")

        wrong_size = copy.deepcopy(valid_document())
        source = wrong_size["source"]
        assert isinstance(source, dict)
        source["size_bytes"] = SOURCE_SIZE + 1
        size_result = evaluate(wrong_size)
        self.assertEqual(size_result.verdict, PartialOracleVerdict.ERROR)
        self.assertEqual(size_result.reason_code, "source_size_mismatch")

    def test_uppercase_digest_is_not_normalized(self) -> None:
        document = valid_document()
        source = document["source"]
        assert isinstance(source, dict)
        source["sha256"] = SOURCE_SHA256.upper()

        result = evaluate(document)

        self.assertEqual(result.verdict, PartialOracleVerdict.ERROR)
        self.assertEqual(result.reason_code, "invalid_schema")

    def test_truncated_oversized_and_noncanonical_payloads_fail_closed(
        self,
    ) -> None:
        valid = canonical_bytes(valid_document())
        cases = {
            "truncated": (valid[:-2], "invalid_json"),
            "oversized": (
                b" " * (REV_INVENTORY_MAX_BYTES + 1),
                "artifact_too_large",
            ),
            "pretty": (
                json.dumps(valid_document(), indent=2).encode("ascii"),
                "noncanonical_json",
            ),
            "trailing": (valid + b"{}", "invalid_json"),
            "bom": (b"\xef\xbb\xbf" + valid, "invalid_json"),
            "invalid_utf8": (b"\xff" + valid, "invalid_json"),
            "nan": (
                valid.replace(b'"bits":64', b'"bits":NaN'),
                "invalid_json",
            ),
            "lone_surrogate": (
                valid.replace(b'"arch":"x86"', b'"arch":"\\ud800"'),
                "invalid_schema",
            ),
        }
        for name, (payload, reason) in cases.items():
            with self.subTest(name=name):
                result = evaluate_rev_inventory(
                    payload,
                    expected_source_sha256=SOURCE_SHA256,
                    expected_source_size_bytes=SOURCE_SIZE,
                )
                self.assertEqual(
                    result.verdict,
                    PartialOracleVerdict.ERROR,
                )
                self.assertEqual(result.reason_code, reason)

    def test_stale_observation_cannot_confirm_a_changed_source(self) -> None:
        stale_payload = canonical_bytes(valid_document())
        current_source = b"\x7fELFchanged-source-same-size"
        current_source = current_source[:SOURCE_SIZE].ljust(SOURCE_SIZE, b"x")
        self.assertEqual(len(current_source), SOURCE_SIZE)
        self.assertNotEqual(current_source, SOURCE_BYTES)

        result = evaluate_rev_inventory(
            stale_payload,
            expected_source_sha256=hashlib.sha256(current_source).hexdigest(),
            expected_source_size_bytes=len(current_source),
        )

        self.assertEqual(result.verdict, PartialOracleVerdict.ERROR)
        self.assertEqual(result.reason_code, "source_hash_mismatch")

    def test_missing_and_unknown_fields_fail_closed(self) -> None:
        missing = valid_document()
        binary = missing["binary"]
        assert isinstance(binary, dict)
        del binary["endian"]

        extra = valid_document()
        binary = extra["binary"]
        assert isinstance(binary, dict)
        binary["confidence"] = 1

        for name, document in (("missing", missing), ("extra", extra)):
            with self.subTest(name=name):
                result = evaluate(document)
                self.assertEqual(
                    result.verdict,
                    PartialOracleVerdict.ERROR,
                )
                self.assertEqual(result.reason_code, "invalid_schema")

    def test_no_code_is_not_applicable(self) -> None:
        document = valid_document()
        binary = document["binary"]
        assert isinstance(binary, dict)
        binary.update(
            {
                "arch": None,
                "bits": None,
                "bintype": "unknown",
                "havecode": False,
            }
        )

        result = evaluate(document)

        self.assertEqual(
            result.verdict,
            PartialOracleVerdict.NOT_APPLICABLE,
        )
        self.assertEqual(result.reason_code, "no_executable_code")

    def test_unsupported_architecture_is_not_applicable(self) -> None:
        document = valid_document()
        binary = document["binary"]
        assert isinstance(binary, dict)
        binary["arch"] = "mystery64"

        result = evaluate(document)

        self.assertEqual(
            result.verdict,
            PartialOracleVerdict.NOT_APPLICABLE,
        )
        self.assertEqual(result.reason_code, "unsupported_architecture")

    def test_incomplete_code_profile_is_inconclusive(self) -> None:
        document = valid_document()
        binary = document["binary"]
        assert isinstance(binary, dict)
        binary["arch"] = None

        result = evaluate(document)

        self.assertEqual(
            result.verdict,
            PartialOracleVerdict.INCONCLUSIVE,
        )
        self.assertEqual(result.reason_code, "incomplete_binary_profile")

    def test_producer_error_is_bound_to_the_source(self) -> None:
        document = valid_document()
        del document["binary"]
        document["status"] = "error"
        document["error"] = {"code": "rabin2_timeout"}

        result = evaluate(document)

        self.assertEqual(result.verdict, PartialOracleVerdict.ERROR)
        self.assertEqual(result.reason_code, "producer_rabin2_timeout")
        self.assertEqual(result.source_sha256, SOURCE_SHA256)
        self.assertEqual(result.source_size_bytes, SOURCE_SIZE)

    def test_trusted_expected_source_arguments_are_strict(self) -> None:
        payload = canonical_bytes(valid_document())
        for sha256, size in (
            (SOURCE_SHA256.upper(), SOURCE_SIZE),
            (SOURCE_SHA256, True),
            (SOURCE_SHA256, -1),
        ):
            with (
                self.subTest(sha256=sha256, size=size),
                self.assertRaises(ValueError),
            ):
                evaluate_rev_inventory(
                    payload,
                    expected_source_sha256=sha256,
                    expected_source_size_bytes=size,
                )


if __name__ == "__main__":
    unittest.main()
