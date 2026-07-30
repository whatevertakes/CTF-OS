"""Pure, fail-closed provenance check for observed Pwn pointer disclosures.

This module deliberately has no execution authority.  It consumes exact,
already-captured bytes from three confirmed positive crash replays and one
final runtime-snapshot replay.  A pointer-shaped token is useful only when it
appears at the same byte offset and with the same width in all four streams,
the final value belongs to a strictly parsed ``/proc/<pid>/maps`` range, and
none of the four values can be found in the exact payload as ASCII or as an
integer encoded at any little-/big-endian width from its minimal width through
eight bytes.

The persisted result never contains raw output, maps text, or address values.
It contains only bounded artifact references, byte offsets, widths, and
SHA-256 commitments.  Every outcome is diagnostic: it cannot prove a leak,
primitive, exploit, proof, or stage transition.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

from ctf_os.contracts.pwn_crash_v1 import (
    PWN_CRASH_V1_CONTRACT_FINGERPRINT,
    PWN_CRASH_V1_POSITIVE_ATTEMPTS,
    PwnCrashV1Verdict,
    pwn_crash_v1_canonical_json_bytes,
)
from ctf_os.contracts.pwn_runtime_snapshot_v1 import (
    PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_FINGERPRINT,
    PWN_RUNTIME_SNAPSHOT_V1_MAX_MAPS_BYTES,
    PwnRuntimeSnapshotV1Status,
)
from ctf_os.engine.pwn_crash import (
    PWN_CRASH_CAPABILITY_PROBE_CONTRACT,
    PWN_CRASH_NETWORK_POLICY,
    PWN_CRASH_ONE_SHOT,
    PWN_CRASH_PRODUCER_CAPABILITY_NAME,
    PWN_CRASH_PRODUCER_FILE_SHA256,
    PWN_CRASH_PRODUCER_INTERPRETER_PATH,
    PWN_CRASH_PRODUCER_PATH,
    PWN_CRASH_SANDBOX_METHOD,
    PwnCrashCapabilityAttestation,
    PwnCrashGateEvaluation,
    PwnCrashReceiptMetadata,
    PwnCrashRecipe,
)
from ctf_os.engine.pwn_runtime_snapshot import (
    PWN_RUNTIME_SNAPSHOT_CAPABILITY_PROBE_CONTRACT,
    PWN_RUNTIME_SNAPSHOT_NETWORK_POLICY,
    PWN_RUNTIME_SNAPSHOT_ONE_SHOT,
    PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME,
    PWN_RUNTIME_SNAPSHOT_PRODUCER_FILE_SHA256,
    PWN_RUNTIME_SNAPSHOT_PRODUCER_INTERPRETER_PATH,
    PWN_RUNTIME_SNAPSHOT_PRODUCER_PATH,
    PWN_RUNTIME_SNAPSHOT_SANDBOX_METHOD,
    PwnRuntimeSnapshotCapabilityAttestation,
    PwnRuntimeSnapshotGateEvaluation,
    PwnRuntimeSnapshotReceiptMetadata,
    PwnRuntimeSnapshotRecipe,
)


PWN_DISCLOSURE_SCHEMA_VERSION = 1
PWN_DISCLOSURE_CONTRACT_ID = "ctfos.pwn.disclosure"
PWN_DISCLOSURE_CONTRACT_VERSION = 1
PWN_DISCLOSURE_POSITIVE_CRASH_REPLAYS = (
    PWN_CRASH_V1_POSITIVE_ATTEMPTS
)
PWN_DISCLOSURE_REPLAY_COUNT = 4
PWN_DISCLOSURE_MAX_CANDIDATES = 32
PWN_DISCLOSURE_MAX_TOKENS_PER_REPLAY = 256
PWN_DISCLOSURE_MAX_STREAM_BYTES = 1024 * 1024
PWN_DISCLOSURE_MAX_PAYLOAD_BYTES = 1024 * 1024
PWN_DISCLOSURE_MAX_MAPS_BYTES = 256 * 1024
PWN_DISCLOSURE_MAX_MAP_LINES = 4096
PWN_DISCLOSURE_MAX_MAP_LINE_BYTES = 8192
PWN_DISCLOSURE_MAX_RESULT_BYTES = 128 * 1024
PWN_DISCLOSURE_MAX_REFERENCE_BYTES = 512
PWN_DISCLOSURE_MAX_REFERENCED_ARTIFACT_BYTES = 64 * 1024 * 1024
PWN_DISCLOSURE_MAX_JSON_DEPTH = 12
PWN_DISCLOSURE_MAX_JSON_NODES = 4096
PWN_DISCLOSURE_MAX_JSON_INTEGER_DIGITS = 20

_U64_MAX = (1 << 64) - 1
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ARTIFACT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,511}$")
_POINTER_TOKEN = re.compile(
    rb"(?<![0-9A-Fa-f])0[xX]([0-9A-Fa-f]{6,16})(?![0-9A-Fa-f])"
)
_MAP_LINE = re.compile(
    rb"(?P<start>[0-9a-f]{1,16})-(?P<end>[0-9a-f]{1,16}) "
    rb"(?P<permissions>[r-][w-][x-][ps]) "
    rb"(?P<offset>[0-9a-f]{1,16}) "
    rb"(?P<major>[0-9a-f]{1,8}):(?P<minor>[0-9a-f]{1,8}) "
    rb"(?P<inode>[0-9]{1,20})(?: (?P<pathname>[\x20-\x7e]+))?"
)

_NON_AUTHORITIES = {
    "leak_proven": False,
    "primitive_proven": False,
    "proof_satisfied": False,
    "stage_advance_authorized": False,
}
_REFERENCE_KEYS = frozenset({"artifact_id", "sha256", "size_bytes"})
_RECEIPT_BINDING_KEYS = frozenset(
    {
        "execution_contract_sha256",
        "ordinal",
        "receipt_id",
        "receipt_sha256",
        "request_sha256",
        "role",
        "run_id",
        "stderr",
        "stdout",
    }
)
_TRUSTED_RECEIPT_EXPECTATION_KEYS = frozenset(
    {
        "positive_receipts",
        "runtime_snapshot_receipt",
        "schema_version",
    }
)
_UPSTREAM_KEYS = frozenset(
    {
        "crash_evaluation_sha256",
        "crash_recipe_sha256",
        "expected_maps_line_count",
        "expected_maps_sha256",
        "expected_maps_size_bytes",
        "expected_payload_sha256",
        "expected_payload_size_bytes",
        "parent_crash_evaluation_sha256",
        "parent_crash_recipe_sha256",
        "positive_receipts",
        "runtime_snapshot_evaluation_sha256",
        "runtime_snapshot_receipt",
        "runtime_snapshot_recipe_sha256",
        "trusted_receipt_expectation_sha256",
    }
)
_BINDING_KEYS = frozenset(
    {
        "crash_stderr",
        "maps",
        "payload",
        "runtime_stderr",
        "upstream",
    }
)
_MAP_COMMITMENT_KEYS = frozenset({"line_index", "line_sha256"})
_CANDIDATE_KEYS = frozenset(
    {
        "byte_offset",
        "distinct_value_count",
        "final_value_sha256",
        "hex_width",
        "mapped_range",
        "payload_derived",
        "replay_value_sha256",
    }
)
_CONTRACT_KEYS = frozenset({"fingerprint", "id", "version"})
_RESULT_KEYS = frozenset(
    {
        "authorities",
        "binding",
        "candidate_count",
        "candidates",
        "contract",
        "reason_code",
        "schema_version",
        "status",
    }
)


def pwn_disclosure_canonical_json_bytes(value: object) -> bytes:
    """Return the canonical persisted JSON encoding used by this contract."""

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


def pwn_disclosure_contract_descriptor() -> dict[str, object]:
    """Return a fresh descriptor covering every v1 acceptance dependency."""

    return {
        "authorities": dict(_NON_AUTHORITIES),
        "artifact_binding": {
            "bytes": "exact-bytes",
            "hash": "sha256(bytes)==typed-receipt-or-recipe-sha256",
            "identity": "exact-artifact-id-sha256-size",
            "identity_pattern": (
                "[A-Za-z0-9][A-Za-z0-9_.:-]{0,511}"
            ),
            "raw_content_in_result": False,
            "reference_id_max_bytes": (
                PWN_DISCLOSURE_MAX_REFERENCE_BYTES
            ),
            "referenced_artifact_max_bytes": (
                PWN_DISCLOSURE_MAX_REFERENCED_ARTIFACT_BYTES
            ),
        },
        "candidate": {
            "commitments": (
                "sha256(case-folded-observed-token)-per-replay;"
                "final-commitment-equals-fourth"
            ),
            "maximum": PWN_DISCLOSURE_MAX_CANDIDATES,
            "maximum_tokens_per_replay": (
                PWN_DISCLOSURE_MAX_TOKENS_PER_REPLAY
            ),
            "order": "byte_offset-then-hex_width",
            "rule": (
                "same-byte-offset-and-hex-width-in-three-positive-"
                "crash-stderr-streams-and-final-runtime-stderr"
            ),
            "token_pattern": "0[xX][0-9a-fA-F]{6,16}",
        },
        "contract_id": PWN_DISCLOSURE_CONTRACT_ID,
        "contract_version": PWN_DISCLOSURE_CONTRACT_VERSION,
        "json": {
            "canonical": "ascii-strict-sorted-compact-final-lf",
            "maximum_depth": PWN_DISCLOSURE_MAX_JSON_DEPTH,
            "maximum_integer_digits": (
                PWN_DISCLOSURE_MAX_JSON_INTEGER_DIGITS
            ),
            "maximum_nodes": PWN_DISCLOSURE_MAX_JSON_NODES,
            "maximum_result_bytes": PWN_DISCLOSURE_MAX_RESULT_BYTES,
            "persisted_validation": (
                "exact-recomputed-PwnDisclosureResult-required"
            ),
        },
        "limits": {
            "maps_bytes": PWN_DISCLOSURE_MAX_MAPS_BYTES,
            "maps_line_bytes": PWN_DISCLOSURE_MAX_MAP_LINE_BYTES,
            "maps_lines": PWN_DISCLOSURE_MAX_MAP_LINES,
            "payload_bytes": PWN_DISCLOSURE_MAX_PAYLOAD_BYTES,
            "stream_bytes": PWN_DISCLOSURE_MAX_STREAM_BYTES,
        },
        "maps": {
            "commitment": (
                "one-based-line-index-plus-sha256(exact-line-with-lf)"
            ),
            "source": (
                "captured-runtime-snapshot-semantic-result-only;"
                "bound-to-snapshot-stdout-receipt"
            ),
            "limit_outcome": (
                "typed-upstream-maps-outside-disclosure-line-or-line-"
                "length-or-byte-bounds=>UNVERIFIABLE:maps_limit_exceeded"
            ),
            "syntax": (
                "complete-final-lf-strict-printable-ascii-proc-maps;"
                "u64-fields;increasing-nonoverlapping-ranges"
            ),
            "syntax_fields": {
                "address": "lowercase-hex-1..16-start<end",
                "device": "lowercase-hex-1..8:lowercase-hex-1..8",
                "inode": "decimal-1..20-u64",
                "offset": "lowercase-hex-1..16-u64",
                "pathname": "optional-nonempty-ascii-0x20..0x7e",
                "permissions": "[r-][w-][x-][ps]",
            },
        },
        "payload_rejection": (
            "any-replay-value-present-as-case-folded-observed-ascii-"
            "token-or-minimal-width-0x-ascii-or-every-integer-width-"
            "from-minimal-through-eight-bytes-in-both-little-and-big-"
            "endian"
        ),
        "provenance": {
            "crash": (
                "exact-canonical-PwnCrashRecipe;"
                "exact-canonical-CONFIRMED-PwnCrashGateEvaluation;"
                "three-canonical-positive-PwnCrashReceiptMetadata;"
                "distinct-ordinals-run-ids-receipt-ids-request-hashes-"
                "execution-contract-hashes;"
                "receipt-stdout-bound-to-confirmed-observations;"
                "receipt-stderr-bound-to-input-bytes"
            ),
            "cross_gate": (
                "same-source-payload-image-epoch-parent-experiment;"
                "snapshot-parent-recipe-and-evaluation-hashes-equal-"
                "canonical-crash-inputs"
            ),
            "receipt_trust_anchor": (
                "distinct-required-PwnDisclosureTrustedReceiptExpectation-"
                "built-by-engine-from-canonical-prior-state-before-"
                "evaluation;exact-positive-and-snapshot-receipt-bindings-"
                "and-canonical-expectation-sha256-must-match"
            ),
            "snapshot": (
                "exact-canonical-PwnRuntimeSnapshotRecipe;"
                "exact-canonical-CAPTURED-"
                "PwnRuntimeSnapshotGateEvaluation;"
                "canonical-PwnRuntimeSnapshotReceiptMetadata;"
                "receipt-stdout-bound-to-captured-semantic-result;"
                "receipt-stderr-bound-to-input-bytes"
            ),
        },
        "replay_count": PWN_DISCLOSURE_REPLAY_COUNT,
        "schema_version": PWN_DISCLOSURE_SCHEMA_VERSION,
        "status_rules": {
            "DYNAMIC_POINTER_OBSERVED": (
                "usable-final-mapped-candidate-with-two-or-more-"
                "distinct-numeric-values"
            ),
            "MAPPED_POINTER_OBSERVED": (
                "usable-final-mapped-candidate-with-one-numeric-value;"
                "no-usable-dynamic-candidate"
            ),
            "UNRESOLVED": (
                "no-common-shape-or-unmapped-or-payload-derived-only"
            ),
            "UNVERIFIABLE": (
                "typed-provenance-or-capture-or-binding-or-parser-"
                "or-bound-failure"
            ),
        },
        "statuses": [
            "DYNAMIC_POINTER_OBSERVED",
            "MAPPED_POINTER_OBSERVED",
            "UNRESOLVED",
            "UNVERIFIABLE",
        ],
        "upstream_acceptance_dependencies": {
            "crash": {
                "capability_probe_contract": (
                    PWN_CRASH_CAPABILITY_PROBE_CONTRACT
                ),
                "contract_fingerprint": (
                    PWN_CRASH_V1_CONTRACT_FINGERPRINT
                ),
                "network_policy": PWN_CRASH_NETWORK_POLICY,
                "one_shot": PWN_CRASH_ONE_SHOT,
                "positive_attempts": PWN_CRASH_V1_POSITIVE_ATTEMPTS,
                "producer_capability_name": (
                    PWN_CRASH_PRODUCER_CAPABILITY_NAME
                ),
                "producer_file_sha256": (
                    PWN_CRASH_PRODUCER_FILE_SHA256
                ),
                "producer_interpreter_path": (
                    PWN_CRASH_PRODUCER_INTERPRETER_PATH
                ),
                "producer_path": PWN_CRASH_PRODUCER_PATH,
                "sandbox_method": PWN_CRASH_SANDBOX_METHOD,
            },
            "runtime_snapshot": {
                "capability_probe_contract": (
                    PWN_RUNTIME_SNAPSHOT_CAPABILITY_PROBE_CONTRACT
                ),
                "contract_fingerprint": (
                    PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_FINGERPRINT
                ),
                "network_policy": (
                    PWN_RUNTIME_SNAPSHOT_NETWORK_POLICY
                ),
                "one_shot": PWN_RUNTIME_SNAPSHOT_ONE_SHOT,
                "semantic_maps_max_bytes": (
                    PWN_RUNTIME_SNAPSHOT_V1_MAX_MAPS_BYTES
                ),
                "producer_capability_name": (
                    PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME
                ),
                "producer_file_sha256": (
                    PWN_RUNTIME_SNAPSHOT_PRODUCER_FILE_SHA256
                ),
                "producer_interpreter_path": (
                    PWN_RUNTIME_SNAPSHOT_PRODUCER_INTERPRETER_PATH
                ),
                "producer_path": (
                    PWN_RUNTIME_SNAPSHOT_PRODUCER_PATH
                ),
                "sandbox_method": (
                    PWN_RUNTIME_SNAPSHOT_SANDBOX_METHOD
                ),
            },
        },
    }


PWN_DISCLOSURE_CONTRACT_FINGERPRINT = hashlib.sha256(
    pwn_disclosure_canonical_json_bytes(
        pwn_disclosure_contract_descriptor()
    )
).hexdigest()


class PwnDisclosureError(ValueError):
    """Stable rejection which never contains attacker-controlled text."""

    def __init__(self, code: str) -> None:
        if type(code) is not str or re.fullmatch(
            r"[a-z][a-z0-9_]{0,127}", code
        ) is None:
            raise ValueError("invalid Pwn disclosure error code")
        super().__init__(code)
        self.code = code


def _require_current_contract_fingerprint() -> None:
    observed = hashlib.sha256(
        pwn_disclosure_canonical_json_bytes(
            pwn_disclosure_contract_descriptor()
        )
    ).hexdigest()
    if observed != PWN_DISCLOSURE_CONTRACT_FINGERPRINT:
        raise PwnDisclosureError("contract_dependency_drift")


class PwnDisclosureStatus(str, Enum):
    DYNAMIC_POINTER_OBSERVED = "DYNAMIC_POINTER_OBSERVED"
    MAPPED_POINTER_OBSERVED = "MAPPED_POINTER_OBSERVED"
    UNRESOLVED = "UNRESOLVED"
    UNVERIFIABLE = "UNVERIFIABLE"


@dataclass(frozen=True, slots=True)
class PwnDisclosureArtifactReference:
    """Bounded immutable reference to durable bytes stored elsewhere."""

    artifact_id: str
    sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        if (
            type(self.artifact_id) is not str
            or len(self.artifact_id.encode("utf-8"))
            > PWN_DISCLOSURE_MAX_REFERENCE_BYTES
            or _ARTIFACT_ID.fullmatch(self.artifact_id) is None
            or type(self.sha256) is not str
            or _SHA256.fullmatch(self.sha256) is None
            or type(self.size_bytes) is not int
            or not 0
            <= self.size_bytes
            <= PWN_DISCLOSURE_MAX_REFERENCED_ARTIFACT_BYTES
        ):
            raise PwnDisclosureError("invalid_artifact_reference")

    def to_dict(self) -> dict[str, object]:
        return {
            "artifact_id": self.artifact_id,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
    ) -> "PwnDisclosureArtifactReference":
        if type(value) is not dict or set(value) != _REFERENCE_KEYS:
            raise PwnDisclosureError("invalid_artifact_reference")
        try:
            result = cls(
                artifact_id=value["artifact_id"],
                sha256=value["sha256"],
                size_bytes=value["size_bytes"],
            )
        except (KeyError, TypeError, ValueError) as error:
            raise PwnDisclosureError(
                "invalid_artifact_reference"
            ) from error
        if value != result.to_dict():
            raise PwnDisclosureError("invalid_artifact_reference")
        return result


@dataclass(frozen=True, slots=True)
class PwnDisclosureReceiptBinding:
    """Raw-free commitment to one canonical typed execution receipt."""

    role: str
    ordinal: int | None
    receipt_id: str
    run_id: str
    receipt_sha256: str
    request_sha256: str
    execution_contract_sha256: str
    stdout: PwnDisclosureArtifactReference
    stderr: PwnDisclosureArtifactReference

    def __post_init__(self) -> None:
        if self.role == "crash_positive":
            ordinal_valid = (
                type(self.ordinal) is int
                and 1
                <= self.ordinal
                <= PWN_DISCLOSURE_POSITIVE_CRASH_REPLAYS
            )
        elif self.role == "runtime_snapshot":
            ordinal_valid = self.ordinal is None
        else:
            ordinal_valid = False
        if (
            not ordinal_valid
            or type(self.receipt_id) is not str
            or _ARTIFACT_ID.fullmatch(self.receipt_id) is None
            or type(self.run_id) is not str
            or _ARTIFACT_ID.fullmatch(self.run_id) is None
            or any(
                type(item) is not str or _SHA256.fullmatch(item) is None
                for item in (
                    self.receipt_sha256,
                    self.request_sha256,
                    self.execution_contract_sha256,
                )
            )
            or type(self.stdout) is not PwnDisclosureArtifactReference
            or type(self.stderr) is not PwnDisclosureArtifactReference
            or self.stdout.artifact_id == self.stderr.artifact_id
        ):
            raise PwnDisclosureError("invalid_receipt_binding")

    def to_dict(self) -> dict[str, object]:
        return {
            "execution_contract_sha256": (
                self.execution_contract_sha256
            ),
            "ordinal": self.ordinal,
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            "request_sha256": self.request_sha256,
            "role": self.role,
            "run_id": self.run_id,
            "stderr": self.stderr.to_dict(),
            "stdout": self.stdout.to_dict(),
        }

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
    ) -> "PwnDisclosureReceiptBinding":
        if (
            type(value) is not dict
            or set(value) != _RECEIPT_BINDING_KEYS
        ):
            raise PwnDisclosureError("invalid_receipt_binding")
        try:
            result = cls(
                role=value["role"],
                ordinal=value["ordinal"],
                receipt_id=value["receipt_id"],
                run_id=value["run_id"],
                receipt_sha256=value["receipt_sha256"],
                request_sha256=value["request_sha256"],
                execution_contract_sha256=value[
                    "execution_contract_sha256"
                ],
                stdout=PwnDisclosureArtifactReference.from_dict(
                    value["stdout"]
                ),
                stderr=PwnDisclosureArtifactReference.from_dict(
                    value["stderr"]
                ),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise PwnDisclosureError("invalid_receipt_binding") from error
        if value != result.to_dict():
            raise PwnDisclosureError("invalid_receipt_binding")
        return result


@dataclass(frozen=True, slots=True)
class PwnDisclosureTrustedReceiptExpectation:
    """Engine-derived receipt trust anchor loaded from canonical prior state.

    The engine must build and persist this value from the already-canonical
    crash/snapshot receipt records *before* invoking the disclosure evaluator.
    The evaluator never derives this expectation from the receipts it is
    currently asked to classify.
    """

    positive_receipts: tuple[PwnDisclosureReceiptBinding, ...]
    runtime_snapshot_receipt: PwnDisclosureReceiptBinding

    def __post_init__(self) -> None:
        if (
            type(self.positive_receipts) is not tuple
            or len(self.positive_receipts)
            != PWN_DISCLOSURE_POSITIVE_CRASH_REPLAYS
            or any(
                type(item) is not PwnDisclosureReceiptBinding
                or item.role != "crash_positive"
                for item in self.positive_receipts
            )
            or tuple(
                item.ordinal for item in self.positive_receipts
            )
            != tuple(
                range(
                    1,
                    PWN_DISCLOSURE_POSITIVE_CRASH_REPLAYS + 1,
                )
            )
            or type(self.runtime_snapshot_receipt)
            is not PwnDisclosureReceiptBinding
            or self.runtime_snapshot_receipt.role != "runtime_snapshot"
        ):
            raise PwnDisclosureError(
                "invalid_trusted_receipt_expectation"
            )
        receipts = (
            *self.positive_receipts,
            self.runtime_snapshot_receipt,
        )
        for attribute in (
            "receipt_id",
            "run_id",
            "receipt_sha256",
            "request_sha256",
            "execution_contract_sha256",
        ):
            values = [getattr(item, attribute) for item in receipts]
            if len(set(values)) != len(values):
                raise PwnDisclosureError(
                    "invalid_trusted_receipt_expectation"
                )
        artifact_ids = [
            stream.artifact_id
            for receipt in receipts
            for stream in (receipt.stdout, receipt.stderr)
        ]
        if len(set(artifact_ids)) != len(artifact_ids):
            raise PwnDisclosureError(
                "invalid_trusted_receipt_expectation"
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "positive_receipts": [
                item.to_dict() for item in self.positive_receipts
            ],
            "runtime_snapshot_receipt": (
                self.runtime_snapshot_receipt.to_dict()
            ),
            "schema_version": PWN_DISCLOSURE_SCHEMA_VERSION,
        }

    def canonical_bytes(self) -> bytes:
        payload = pwn_disclosure_canonical_json_bytes(self.to_dict())
        if len(payload) > PWN_DISCLOSURE_MAX_RESULT_BYTES:
            raise PwnDisclosureError(
                "trusted_receipt_expectation_size_exceeded"
            )
        return payload

    @property
    def evidence_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
    ) -> "PwnDisclosureTrustedReceiptExpectation":
        if (
            type(value) is not dict
            or set(value) != _TRUSTED_RECEIPT_EXPECTATION_KEYS
            or value.get("schema_version")
            != PWN_DISCLOSURE_SCHEMA_VERSION
            or type(value.get("positive_receipts")) is not list
            or len(value["positive_receipts"])
            != PWN_DISCLOSURE_POSITIVE_CRASH_REPLAYS
        ):
            raise PwnDisclosureError(
                "invalid_trusted_receipt_expectation"
            )
        try:
            result = cls(
                positive_receipts=tuple(
                    PwnDisclosureReceiptBinding.from_dict(item)
                    for item in value["positive_receipts"]
                ),
                runtime_snapshot_receipt=(
                    PwnDisclosureReceiptBinding.from_dict(
                        value["runtime_snapshot_receipt"]
                    )
                ),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise PwnDisclosureError(
                "invalid_trusted_receipt_expectation"
            ) from error
        if value != result.to_dict():
            raise PwnDisclosureError(
                "invalid_trusted_receipt_expectation"
            )
        result.canonical_bytes()
        return result


@dataclass(frozen=True, slots=True)
class PwnDisclosureUpstreamBinding:
    """Canonical hashes and receipt identities joining both prior gates."""

    crash_recipe_sha256: str
    crash_evaluation_sha256: str
    runtime_snapshot_recipe_sha256: str
    runtime_snapshot_evaluation_sha256: str
    trusted_receipt_expectation_sha256: str
    parent_crash_recipe_sha256: str
    parent_crash_evaluation_sha256: str
    positive_receipts: tuple[PwnDisclosureReceiptBinding, ...]
    runtime_snapshot_receipt: PwnDisclosureReceiptBinding
    expected_payload_sha256: str
    expected_payload_size_bytes: int
    expected_maps_sha256: str
    expected_maps_size_bytes: int
    expected_maps_line_count: int

    def __post_init__(self) -> None:
        if (
            any(
                type(item) is not str or _SHA256.fullmatch(item) is None
                for item in (
                    self.crash_recipe_sha256,
                    self.crash_evaluation_sha256,
                    self.runtime_snapshot_recipe_sha256,
                    self.runtime_snapshot_evaluation_sha256,
                    self.trusted_receipt_expectation_sha256,
                    self.parent_crash_recipe_sha256,
                    self.parent_crash_evaluation_sha256,
                )
            )
            or type(self.positive_receipts) is not tuple
            or len(self.positive_receipts)
            != PWN_DISCLOSURE_POSITIVE_CRASH_REPLAYS
            or any(
                type(item) is not PwnDisclosureReceiptBinding
                or item.role != "crash_positive"
                for item in self.positive_receipts
            )
            or type(self.runtime_snapshot_receipt)
            is not PwnDisclosureReceiptBinding
            or self.runtime_snapshot_receipt.role != "runtime_snapshot"
            or type(self.expected_payload_sha256) is not str
            or _SHA256.fullmatch(self.expected_payload_sha256) is None
            or type(self.expected_payload_size_bytes) is not int
            or not 1
            <= self.expected_payload_size_bytes
            <= PWN_DISCLOSURE_MAX_PAYLOAD_BYTES
            or type(self.expected_maps_sha256) is not str
            or _SHA256.fullmatch(self.expected_maps_sha256) is None
            or type(self.expected_maps_size_bytes) is not int
            or not 0
            <= self.expected_maps_size_bytes
            <= PWN_DISCLOSURE_MAX_MAPS_BYTES
            or type(self.expected_maps_line_count) is not int
            or not 0
            <= self.expected_maps_line_count
            <= PWN_RUNTIME_SNAPSHOT_V1_MAX_MAPS_BYTES
            or (
                self.expected_maps_size_bytes == 0
            )
            is not (self.expected_maps_line_count == 0)
        ):
            raise PwnDisclosureError("invalid_upstream_binding")

    def to_dict(self) -> dict[str, object]:
        return {
            "crash_evaluation_sha256": self.crash_evaluation_sha256,
            "crash_recipe_sha256": self.crash_recipe_sha256,
            "expected_maps_line_count": self.expected_maps_line_count,
            "expected_maps_sha256": self.expected_maps_sha256,
            "expected_maps_size_bytes": self.expected_maps_size_bytes,
            "expected_payload_sha256": self.expected_payload_sha256,
            "expected_payload_size_bytes": (
                self.expected_payload_size_bytes
            ),
            "parent_crash_evaluation_sha256": (
                self.parent_crash_evaluation_sha256
            ),
            "parent_crash_recipe_sha256": (
                self.parent_crash_recipe_sha256
            ),
            "positive_receipts": [
                item.to_dict() for item in self.positive_receipts
            ],
            "runtime_snapshot_evaluation_sha256": (
                self.runtime_snapshot_evaluation_sha256
            ),
            "runtime_snapshot_receipt": (
                self.runtime_snapshot_receipt.to_dict()
            ),
            "runtime_snapshot_recipe_sha256": (
                self.runtime_snapshot_recipe_sha256
            ),
            "trusted_receipt_expectation_sha256": (
                self.trusted_receipt_expectation_sha256
            ),
        }

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
    ) -> "PwnDisclosureUpstreamBinding":
        if type(value) is not dict or set(value) != _UPSTREAM_KEYS:
            raise PwnDisclosureError("invalid_upstream_binding")
        receipts = value.get("positive_receipts")
        if (
            type(receipts) is not list
            or len(receipts)
            != PWN_DISCLOSURE_POSITIVE_CRASH_REPLAYS
        ):
            raise PwnDisclosureError("invalid_upstream_binding")
        try:
            result = cls(
                crash_recipe_sha256=value["crash_recipe_sha256"],
                crash_evaluation_sha256=value[
                    "crash_evaluation_sha256"
                ],
                runtime_snapshot_recipe_sha256=value[
                    "runtime_snapshot_recipe_sha256"
                ],
                runtime_snapshot_evaluation_sha256=value[
                    "runtime_snapshot_evaluation_sha256"
                ],
                trusted_receipt_expectation_sha256=value[
                    "trusted_receipt_expectation_sha256"
                ],
                parent_crash_recipe_sha256=value[
                    "parent_crash_recipe_sha256"
                ],
                parent_crash_evaluation_sha256=value[
                    "parent_crash_evaluation_sha256"
                ],
                positive_receipts=tuple(
                    PwnDisclosureReceiptBinding.from_dict(item)
                    for item in receipts
                ),
                runtime_snapshot_receipt=(
                    PwnDisclosureReceiptBinding.from_dict(
                        value["runtime_snapshot_receipt"]
                    )
                ),
                expected_payload_sha256=value[
                    "expected_payload_sha256"
                ],
                expected_payload_size_bytes=value[
                    "expected_payload_size_bytes"
                ],
                expected_maps_sha256=value["expected_maps_sha256"],
                expected_maps_size_bytes=value[
                    "expected_maps_size_bytes"
                ],
                expected_maps_line_count=value[
                    "expected_maps_line_count"
                ],
            )
        except (KeyError, TypeError, ValueError) as error:
            raise PwnDisclosureError(
                "invalid_upstream_binding"
            ) from error
        if value != result.to_dict():
            raise PwnDisclosureError("invalid_upstream_binding")
        return result


@dataclass(frozen=True, slots=True)
class PwnDisclosureResultBinding:
    """Raw-free persisted identity of all evaluator inputs."""

    upstream: PwnDisclosureUpstreamBinding
    payload: PwnDisclosureArtifactReference
    crash_stderr: tuple[PwnDisclosureArtifactReference, ...]
    runtime_stderr: PwnDisclosureArtifactReference
    maps: PwnDisclosureArtifactReference

    def __post_init__(self) -> None:
        if (
            type(self.upstream) is not PwnDisclosureUpstreamBinding
            or type(self.payload) is not PwnDisclosureArtifactReference
            or type(self.crash_stderr) is not tuple
            or len(self.crash_stderr)
            != PWN_DISCLOSURE_POSITIVE_CRASH_REPLAYS
            or any(
                type(item) is not PwnDisclosureArtifactReference
                for item in self.crash_stderr
            )
            or type(self.runtime_stderr)
            is not PwnDisclosureArtifactReference
            or type(self.maps) is not PwnDisclosureArtifactReference
        ):
            raise PwnDisclosureError("invalid_result_binding")
        if (
            self.payload.sha256
            != self.upstream.expected_payload_sha256
            or self.payload.size_bytes
            != self.upstream.expected_payload_size_bytes
            or self.crash_stderr
            != tuple(
                item.stderr for item in self.upstream.positive_receipts
            )
            or self.runtime_stderr
            != self.upstream.runtime_snapshot_receipt.stderr
            or self.maps
            != self.upstream.runtime_snapshot_receipt.stdout
        ):
            raise PwnDisclosureError("result_binding_mismatch")

    def to_dict(self) -> dict[str, object]:
        return {
            "crash_stderr": [
                item.to_dict() for item in self.crash_stderr
            ],
            "maps": self.maps.to_dict(),
            "payload": self.payload.to_dict(),
            "runtime_stderr": self.runtime_stderr.to_dict(),
            "upstream": self.upstream.to_dict(),
        }

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
    ) -> "PwnDisclosureResultBinding":
        if type(value) is not dict or set(value) != _BINDING_KEYS:
            raise PwnDisclosureError("invalid_result_binding")
        crash_value = value.get("crash_stderr")
        if (
            type(crash_value) is not list
            or len(crash_value) != PWN_DISCLOSURE_POSITIVE_CRASH_REPLAYS
        ):
            raise PwnDisclosureError("invalid_result_binding")
        try:
            result = cls(
                upstream=PwnDisclosureUpstreamBinding.from_dict(
                    value["upstream"]
                ),
                payload=PwnDisclosureArtifactReference.from_dict(
                    value["payload"]
                ),
                crash_stderr=tuple(
                    PwnDisclosureArtifactReference.from_dict(item)
                    for item in crash_value
                ),
                runtime_stderr=(
                    PwnDisclosureArtifactReference.from_dict(
                        value["runtime_stderr"]
                    )
                ),
                maps=PwnDisclosureArtifactReference.from_dict(
                    value["maps"]
                ),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise PwnDisclosureError("invalid_result_binding") from error
        if value != result.to_dict():
            raise PwnDisclosureError("invalid_result_binding")
        return result


@dataclass(frozen=True, slots=True)
class PwnDisclosureMapRange:
    """One strictly parsed range; never serialized into a result."""

    start: int
    end: int
    line_index: int
    line_sha256: str

    def contains(self, value: int) -> bool:
        return self.start <= value < self.end


@dataclass(frozen=True, slots=True)
class PwnDisclosureMapCommitment:
    line_index: int
    line_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.line_index) is not int
            or not 1 <= self.line_index <= PWN_DISCLOSURE_MAX_MAP_LINES
            or type(self.line_sha256) is not str
            or _SHA256.fullmatch(self.line_sha256) is None
        ):
            raise PwnDisclosureError("invalid_map_commitment")

    def to_dict(self) -> dict[str, object]:
        return {
            "line_index": self.line_index,
            "line_sha256": self.line_sha256,
        }

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
    ) -> "PwnDisclosureMapCommitment":
        if type(value) is not dict or set(value) != _MAP_COMMITMENT_KEYS:
            raise PwnDisclosureError("invalid_map_commitment")
        try:
            result = cls(
                line_index=value["line_index"],
                line_sha256=value["line_sha256"],
            )
        except (KeyError, TypeError, ValueError) as error:
            raise PwnDisclosureError("invalid_map_commitment") from error
        if value != result.to_dict():
            raise PwnDisclosureError("invalid_map_commitment")
        return result


@dataclass(frozen=True, slots=True)
class PwnDisclosureCandidate:
    """Raw-free commitment to one common pointer-shaped observation."""

    byte_offset: int
    hex_width: int
    replay_value_sha256: tuple[str, ...]
    distinct_value_count: int
    final_value_sha256: str
    mapped_range: PwnDisclosureMapCommitment | None
    payload_derived: bool

    def __post_init__(self) -> None:
        if (
            type(self.byte_offset) is not int
            or not 0
            <= self.byte_offset
            < PWN_DISCLOSURE_MAX_STREAM_BYTES
            or type(self.hex_width) is not int
            or not 6 <= self.hex_width <= 16
            or type(self.replay_value_sha256) is not tuple
            or len(self.replay_value_sha256)
            != PWN_DISCLOSURE_REPLAY_COUNT
            or any(
                type(item) is not str
                or _SHA256.fullmatch(item) is None
                for item in self.replay_value_sha256
            )
            or type(self.distinct_value_count) is not int
            or self.distinct_value_count
            != len(set(self.replay_value_sha256))
            or not 1
            <= self.distinct_value_count
            <= PWN_DISCLOSURE_REPLAY_COUNT
            or type(self.final_value_sha256) is not str
            or self.final_value_sha256
            != self.replay_value_sha256[-1]
            or (
                self.mapped_range is not None
                and type(self.mapped_range)
                is not PwnDisclosureMapCommitment
            )
            or type(self.payload_derived) is not bool
        ):
            raise PwnDisclosureError("invalid_candidate")

    @property
    def usable(self) -> bool:
        return self.mapped_range is not None and not self.payload_derived

    def to_dict(self) -> dict[str, object]:
        return {
            "byte_offset": self.byte_offset,
            "distinct_value_count": self.distinct_value_count,
            "final_value_sha256": self.final_value_sha256,
            "hex_width": self.hex_width,
            "mapped_range": (
                None
                if self.mapped_range is None
                else self.mapped_range.to_dict()
            ),
            "payload_derived": self.payload_derived,
            "replay_value_sha256": list(self.replay_value_sha256),
        }

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
    ) -> "PwnDisclosureCandidate":
        if type(value) is not dict or set(value) != _CANDIDATE_KEYS:
            raise PwnDisclosureError("invalid_candidate")
        hashes = value.get("replay_value_sha256")
        mapped_value = value.get("mapped_range")
        if type(hashes) is not list:
            raise PwnDisclosureError("invalid_candidate")
        try:
            result = cls(
                byte_offset=value["byte_offset"],
                hex_width=value["hex_width"],
                replay_value_sha256=tuple(hashes),
                distinct_value_count=value["distinct_value_count"],
                final_value_sha256=value["final_value_sha256"],
                mapped_range=(
                    None
                    if mapped_value is None
                    else PwnDisclosureMapCommitment.from_dict(
                        mapped_value
                    )
                ),
                payload_derived=value["payload_derived"],
            )
        except (KeyError, TypeError, ValueError) as error:
            raise PwnDisclosureError("invalid_candidate") from error
        if value != result.to_dict():
            raise PwnDisclosureError("invalid_candidate")
        return result


_UNVERIFIABLE_REASONS = frozenset(
    {
        "artifact_binding_mismatch",
        "artifact_size_limit_exceeded",
        "candidate_limit_exceeded",
        "crash_gate_not_confirmed",
        "malformed_maps",
        "maps_binding_mismatch",
        "maps_limit_exceeded",
        "provenance_binding_mismatch",
        "receipt_binding_mismatch",
        "snapshot_gate_not_captured",
        "typed_provenance_invalid",
    }
)
_UNRESOLVED_REASONS = frozenset(
    {
        "common_pointer_unmapped",
        "no_common_pointer_shape",
        "payload_echo_only",
    }
)


@dataclass(frozen=True, slots=True)
class PwnDisclosureResult:
    status: PwnDisclosureStatus
    reason_code: str
    binding: PwnDisclosureResultBinding
    candidates: tuple[PwnDisclosureCandidate, ...]

    def __post_init__(self) -> None:
        if (
            type(self.status) is not PwnDisclosureStatus
            or type(self.reason_code) is not str
            or type(self.binding) is not PwnDisclosureResultBinding
            or type(self.candidates) is not tuple
            or len(self.candidates) > PWN_DISCLOSURE_MAX_CANDIDATES
            or any(
                type(item) is not PwnDisclosureCandidate
                for item in self.candidates
            )
        ):
            raise PwnDisclosureError("invalid_result")
        order = tuple(
            (item.byte_offset, item.hex_width) for item in self.candidates
        )
        if order != tuple(sorted(order)) or len(set(order)) != len(order):
            raise PwnDisclosureError("candidate_order_mismatch")
        dynamic = any(
            item.usable and item.distinct_value_count >= 2
            for item in self.candidates
        )
        fixed = any(
            item.usable and item.distinct_value_count == 1
            for item in self.candidates
        )
        if self.status is PwnDisclosureStatus.DYNAMIC_POINTER_OBSERVED:
            valid = self.reason_code == "dynamic_pointer_observed" and dynamic
        elif (
            self.status
            is PwnDisclosureStatus.MAPPED_POINTER_OBSERVED
        ):
            valid = (
                self.reason_code == "mapped_pointer_observed"
                and not dynamic
                and fixed
            )
        elif self.status is PwnDisclosureStatus.UNRESOLVED:
            valid = (
                self.reason_code in _UNRESOLVED_REASONS
                and not dynamic
                and not fixed
            )
            if self.reason_code == "no_common_pointer_shape":
                valid = valid and not self.candidates
            elif self.reason_code == "payload_echo_only":
                valid = valid and any(
                    item.mapped_range is not None
                    and item.payload_derived
                    for item in self.candidates
                )
            elif self.reason_code == "common_pointer_unmapped":
                valid = valid and bool(self.candidates) and all(
                    item.mapped_range is None
                    or item.payload_derived
                    for item in self.candidates
                )
        else:
            valid = (
                self.reason_code in _UNVERIFIABLE_REASONS
                and not self.candidates
            )
        if not valid:
            raise PwnDisclosureError("result_semantic_mismatch")

    def to_dict(self) -> dict[str, object]:
        return {
            "authorities": dict(_NON_AUTHORITIES),
            "binding": self.binding.to_dict(),
            "candidate_count": len(self.candidates),
            "candidates": [item.to_dict() for item in self.candidates],
            "contract": {
                "fingerprint": PWN_DISCLOSURE_CONTRACT_FINGERPRINT,
                "id": PWN_DISCLOSURE_CONTRACT_ID,
                "version": PWN_DISCLOSURE_CONTRACT_VERSION,
            },
            "reason_code": self.reason_code,
            "schema_version": PWN_DISCLOSURE_SCHEMA_VERSION,
            "status": self.status.value,
        }

    def canonical_bytes(self) -> bytes:
        payload = pwn_disclosure_canonical_json_bytes(self.to_dict())
        if len(payload) > PWN_DISCLOSURE_MAX_RESULT_BYTES:
            raise PwnDisclosureError("result_size_limit_exceeded")
        return payload

    @property
    def evidence_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
        *,
        expected_result: "PwnDisclosureResult",
    ) -> "PwnDisclosureResult":
        if type(expected_result) is not PwnDisclosureResult:
            raise PwnDisclosureError("expected_result_required")
        if type(value) is not dict or set(value) != _RESULT_KEYS:
            raise PwnDisclosureError("invalid_result")
        if (
            value.get("schema_version") != PWN_DISCLOSURE_SCHEMA_VERSION
            or value.get("authorities") != _NON_AUTHORITIES
            or value.get("contract")
            != {
                "fingerprint": PWN_DISCLOSURE_CONTRACT_FINGERPRINT,
                "id": PWN_DISCLOSURE_CONTRACT_ID,
                "version": PWN_DISCLOSURE_CONTRACT_VERSION,
            }
            or type(value.get("candidate_count")) is not int
            or type(value.get("candidates")) is not list
            or value.get("candidate_count") != len(value["candidates"])
        ):
            raise PwnDisclosureError("invalid_result")
        try:
            result = cls(
                status=PwnDisclosureStatus(value["status"]),
                reason_code=value["reason_code"],
                binding=PwnDisclosureResultBinding.from_dict(
                    value["binding"]
                ),
                candidates=tuple(
                    PwnDisclosureCandidate.from_dict(item)
                    for item in value["candidates"]
                ),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise PwnDisclosureError("invalid_result") from error
        if value != result.to_dict():
            raise PwnDisclosureError("result_not_reconstructable")
        result.canonical_bytes()
        if result.to_dict() != expected_result.to_dict():
            raise PwnDisclosureError("result_binding_mismatch")
        return result


def _validate_json_tree(value: object) -> None:
    pending = [(value, 1)]
    nodes = 0
    while pending:
        current, depth = pending.pop()
        nodes += 1
        if (
            depth > PWN_DISCLOSURE_MAX_JSON_DEPTH
            or nodes > PWN_DISCLOSURE_MAX_JSON_NODES
        ):
            raise PwnDisclosureError("result_structure_limit_exceeded")
        if type(current) is dict:
            if any(type(key) is not str for key in current):
                raise PwnDisclosureError("invalid_result")
            pending.extend(
                (item, depth + 1) for item in current.values()
            )
        elif type(current) is list:
            pending.extend((item, depth + 1) for item in current)
        elif type(current) not in {str, int, bool, type(None)}:
            raise PwnDisclosureError("invalid_result")


def _precheck_json_resource_limits(payload: bytes) -> None:
    """Bound nesting before decoding while ignoring brackets in strings."""

    depth = 0
    in_string = False
    escaped = False
    for byte in payload:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in {0x5B, 0x7B}:
            depth += 1
            if depth > PWN_DISCLOSURE_MAX_JSON_DEPTH:
                raise PwnDisclosureError("invalid_json")
        elif byte in {0x5D, 0x7D}:
            depth -= 1
            if depth < 0:
                raise PwnDisclosureError("invalid_json")
    if in_string or escaped or depth != 0:
        raise PwnDisclosureError("invalid_json")


def _parse_bounded_json_int(value: str) -> int:
    digits = value[1:] if value.startswith("-") else value
    if (
        not digits
        or len(digits) > PWN_DISCLOSURE_MAX_JSON_INTEGER_DIGITS
    ):
        raise PwnDisclosureError("invalid_json")
    try:
        return int(value, 10)
    except ValueError as error:
        raise PwnDisclosureError("invalid_json") from error


def validate_pwn_disclosure_result(
    value: Mapping[str, object],
    *,
    expected_result: PwnDisclosureResult,
) -> PwnDisclosureResult:
    """Validate a result dict only against an exact recomputed result."""

    _validate_json_tree(value)
    return PwnDisclosureResult.from_dict(
        value,
        expected_result=expected_result,
    )


def parse_pwn_disclosure_result(
    payload: bytes,
    *,
    expected_result: PwnDisclosureResult,
) -> PwnDisclosureResult:
    """Parse only bounded duplicate-free canonical result bytes."""

    if (
        type(payload) is not bytes
        or not 1 <= len(payload) <= PWN_DISCLOSURE_MAX_RESULT_BYTES
    ):
        raise PwnDisclosureError("result_size_limit_exceeded")
    _precheck_json_resource_limits(payload)

    def reject_duplicates(
        pairs: list[tuple[str, Any]],
    ) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise PwnDisclosureError("duplicate_json_key")
            result[key] = item
        return result

    try:
        value = json.loads(
            payload.decode("ascii"),
            object_pairs_hook=reject_duplicates,
            parse_int=_parse_bounded_json_int,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                PwnDisclosureError("invalid_json")
            ),
        )
    except PwnDisclosureError:
        raise
    except (
        RecursionError,
        UnicodeDecodeError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        raise PwnDisclosureError("invalid_json") from error
    result = validate_pwn_disclosure_result(
        value,
        expected_result=expected_result,
    )
    if payload != result.canonical_bytes():
        raise PwnDisclosureError("noncanonical_json")
    return result


def pwn_disclosure_result_sha256(
    value: PwnDisclosureResult,
) -> str:
    """Hash one already recomputed exact result."""

    if type(value) is not PwnDisclosureResult:
        raise PwnDisclosureError("invalid_result")
    return value.evidence_sha256


def parse_pwn_disclosure_maps(
    data: bytes,
) -> tuple[PwnDisclosureMapRange, ...]:
    """Strictly parse one complete bounded ASCII ``/proc/<pid>/maps``."""

    if (
        type(data) is not bytes
        or not 1 <= len(data) <= PWN_DISCLOSURE_MAX_MAPS_BYTES
        or not data.endswith(b"\n")
        or b"\x00" in data
    ):
        raise PwnDisclosureError("malformed_maps")
    lines = data[:-1].split(b"\n")
    if (
        not lines
        or len(lines) > PWN_DISCLOSURE_MAX_MAP_LINES
        or any(
            not line or len(line) > PWN_DISCLOSURE_MAX_MAP_LINE_BYTES
            for line in lines
        )
    ):
        raise PwnDisclosureError("malformed_maps")
    result: list[PwnDisclosureMapRange] = []
    previous_end = 0
    for index, line in enumerate(lines, start=1):
        match = _MAP_LINE.fullmatch(line)
        if match is None:
            raise PwnDisclosureError("malformed_maps")
        try:
            start = int(match.group("start"), 16)
            end = int(match.group("end"), 16)
            offset = int(match.group("offset"), 16)
            major = int(match.group("major"), 16)
            minor = int(match.group("minor"), 16)
            inode = int(match.group("inode"), 10)
        except ValueError as error:
            raise PwnDisclosureError("malformed_maps") from error
        if (
            any(
                item < 0 or item > _U64_MAX
                for item in (start, end, offset, major, minor, inode)
            )
            or start >= end
            or (result and start < previous_end)
        ):
            raise PwnDisclosureError("malformed_maps")
        result.append(
            PwnDisclosureMapRange(
                start=start,
                end=end,
                line_index=index,
                line_sha256=hashlib.sha256(line + b"\n").hexdigest(),
            )
        )
        previous_end = end
    return tuple(result)


@dataclass(frozen=True, slots=True)
class _Token:
    byte_offset: int
    width: int
    raw: bytes
    value: int


def _extract_tokens(data: bytes) -> dict[tuple[int, int], _Token]:
    result: dict[tuple[int, int], _Token] = {}
    for match in _POINTER_TOKEN.finditer(data):
        if len(result) >= PWN_DISCLOSURE_MAX_TOKENS_PER_REPLAY:
            raise PwnDisclosureError("candidate_limit_exceeded")
        digits = match.group(1)
        token = _Token(
            byte_offset=match.start(),
            width=len(digits),
            raw=match.group(0),
            value=int(digits, 16),
        )
        result[(token.byte_offset, token.width)] = token
    return result


def _artifact_problem(
    data: bytes,
    reference: PwnDisclosureArtifactReference,
    *,
    maximum_bytes: int,
) -> str | None:
    if (
        type(data) is not bytes
        or len(data) > maximum_bytes
        or reference.size_bytes > maximum_bytes
    ):
        return "artifact_size_limit_exceeded"
    if (
        len(data) != reference.size_bytes
        or hashlib.sha256(data).hexdigest() != reference.sha256
    ):
        return "artifact_binding_mismatch"
    return None


def _find_range(
    ranges: Sequence[PwnDisclosureMapRange],
    value: int,
) -> PwnDisclosureMapRange | None:
    for item in ranges:
        if item.contains(value):
            return item
        if item.start > value:
            break
    return None


def _payload_contains(
    payload: bytes,
    tokens: Sequence[_Token],
) -> bool:
    lowered = payload.lower()
    for token in tokens:
        minimal = f"0x{token.value:x}".encode("ascii")
        if token.raw.lower() in lowered or minimal in lowered:
            return True
        minimal_size = max(1, (token.value.bit_length() + 7) // 8)
        for width in range(minimal_size, 9):
            if (
                token.value.to_bytes(width, "little") in payload
                or token.value.to_bytes(width, "big") in payload
            ):
                return True
    return False


def _unverifiable(
    reason_code: str,
    binding: PwnDisclosureResultBinding,
) -> PwnDisclosureResult:
    return PwnDisclosureResult(
        status=PwnDisclosureStatus.UNVERIFIABLE,
        reason_code=reason_code,
        binding=binding,
        candidates=(),
    )


def _artifact_reference(
    artifact_id: object,
    sha256: object,
    size_bytes: object,
) -> PwnDisclosureArtifactReference:
    try:
        return PwnDisclosureArtifactReference(
            artifact_id=artifact_id,
            sha256=sha256,
            size_bytes=size_bytes,
        )
    except (TypeError, ValueError) as error:
        raise PwnDisclosureError("typed_provenance_invalid") from error


def _receipt_sha256(receipt: object) -> str:
    try:
        value = receipt.to_dict()
        return hashlib.sha256(
            pwn_disclosure_canonical_json_bytes(value)
        ).hexdigest()
    except (AttributeError, RecursionError, TypeError, ValueError) as error:
        raise PwnDisclosureError("typed_provenance_invalid") from error


def _crash_receipt_binding(
    receipt: PwnCrashReceiptMetadata,
) -> PwnDisclosureReceiptBinding:
    return PwnDisclosureReceiptBinding(
        role="crash_positive",
        ordinal=receipt.ordinal,
        receipt_id=receipt.receipt_id,
        run_id=receipt.run_id,
        receipt_sha256=_receipt_sha256(receipt),
        request_sha256=receipt.request_sha256,
        execution_contract_sha256=(
            receipt.execution_contract_sha256
        ),
        stdout=_artifact_reference(
            receipt.stdout_artifact_id,
            receipt.stdout_artifact_sha256,
            receipt.stdout_artifact_size_bytes,
        ),
        stderr=_artifact_reference(
            receipt.stderr_artifact_id,
            receipt.stderr_artifact_sha256,
            receipt.stderr_artifact_size_bytes,
        ),
    )


def _snapshot_receipt_binding(
    receipt: PwnRuntimeSnapshotReceiptMetadata,
) -> PwnDisclosureReceiptBinding:
    return PwnDisclosureReceiptBinding(
        role="runtime_snapshot",
        ordinal=None,
        receipt_id=receipt.receipt_id,
        run_id=receipt.run_id,
        receipt_sha256=_receipt_sha256(receipt),
        request_sha256=receipt.request_sha256,
        execution_contract_sha256=(
            receipt.execution_contract_sha256
        ),
        stdout=_artifact_reference(
            receipt.stdout_artifact_id,
            receipt.stdout_artifact_sha256,
            receipt.stdout_artifact_size_bytes,
        ),
        stderr=_artifact_reference(
            receipt.stderr_artifact_id,
            receipt.stderr_artifact_sha256,
            receipt.stderr_artifact_size_bytes,
        ),
    )


def build_pwn_disclosure_trusted_receipt_expectation(
    *,
    positive_crash_receipts: tuple[PwnCrashReceiptMetadata, ...],
    snapshot_receipt: PwnRuntimeSnapshotReceiptMetadata,
) -> PwnDisclosureTrustedReceiptExpectation:
    """Build the trust anchor while reading canonical prior engine state.

    This function must be called at the canonical-state boundary, before any
    disclosure evaluation inputs can be replaced.  Passing a value freshly
    derived from the same untrusted receipts supplied to
    :func:`evaluate_pwn_disclosure` defeats that boundary and is unsupported.
    """

    if (
        type(positive_crash_receipts) is not tuple
        or len(positive_crash_receipts)
        != PWN_DISCLOSURE_POSITIVE_CRASH_REPLAYS
        or any(
            type(item) is not PwnCrashReceiptMetadata
            for item in positive_crash_receipts
        )
        or type(snapshot_receipt)
        is not PwnRuntimeSnapshotReceiptMetadata
    ):
        raise TypeError("canonical typed receipt records are required")
    _require_current_contract_fingerprint()
    try:
        canonical_crash = tuple(
            PwnCrashReceiptMetadata.from_dict(item.to_dict())
            for item in positive_crash_receipts
        )
        canonical_snapshot = (
            PwnRuntimeSnapshotReceiptMetadata.from_dict(
                snapshot_receipt.to_dict()
            )
        )
    except (RecursionError, TypeError, ValueError) as error:
        raise PwnDisclosureError(
            "invalid_trusted_receipt_expectation"
        ) from error
    result = PwnDisclosureTrustedReceiptExpectation(
        positive_receipts=tuple(
            _crash_receipt_binding(item) for item in canonical_crash
        ),
        runtime_snapshot_receipt=_snapshot_receipt_binding(
            canonical_snapshot
        ),
    )
    return PwnDisclosureTrustedReceiptExpectation.from_dict(
        result.to_dict()
    )


def _reconstruct_typed_provenance(
    *,
    crash_recipe: PwnCrashRecipe,
    crash_evaluation: PwnCrashGateEvaluation,
    positive_crash_receipts: tuple[PwnCrashReceiptMetadata, ...],
    snapshot_recipe: PwnRuntimeSnapshotRecipe,
    snapshot_evaluation: PwnRuntimeSnapshotGateEvaluation,
    snapshot_receipt: PwnRuntimeSnapshotReceiptMetadata,
    trusted_receipt_expectation: (
        PwnDisclosureTrustedReceiptExpectation
    ),
) -> None:
    """Reject forged instances which bypassed canonical constructors."""

    try:
        if (
            PwnCrashRecipe.from_dict(crash_recipe.to_dict())
            != crash_recipe
            or PwnCrashGateEvaluation.from_dict(
                crash_evaluation.to_dict()
            )
            != crash_evaluation
            or PwnRuntimeSnapshotRecipe.from_dict(
                snapshot_recipe.to_dict()
            )
            != snapshot_recipe
            or PwnRuntimeSnapshotGateEvaluation.from_dict(
                snapshot_evaluation.to_dict(),
                recipe=snapshot_recipe,
            )
            != snapshot_evaluation
            or PwnRuntimeSnapshotReceiptMetadata.from_dict(
                snapshot_receipt.to_dict()
            )
            != snapshot_receipt
            or PwnDisclosureTrustedReceiptExpectation.from_dict(
                trusted_receipt_expectation.to_dict()
            )
            != trusted_receipt_expectation
            or any(
                PwnCrashReceiptMetadata.from_dict(item.to_dict())
                != item
                for item in positive_crash_receipts
            )
        ):
            raise PwnDisclosureError("typed_provenance_invalid")
    except PwnDisclosureError:
        raise
    except (RecursionError, TypeError, ValueError) as error:
        raise PwnDisclosureError("typed_provenance_invalid") from error


def _result_binding(
    *,
    crash_recipe: PwnCrashRecipe,
    crash_evaluation: PwnCrashGateEvaluation,
    snapshot_recipe: PwnRuntimeSnapshotRecipe,
    snapshot_evaluation: PwnRuntimeSnapshotGateEvaluation,
    trusted_receipt_expectation: (
        PwnDisclosureTrustedReceiptExpectation
    ),
) -> PwnDisclosureResultBinding:
    positive = trusted_receipt_expectation.positive_receipts
    snapshot = trusted_receipt_expectation.runtime_snapshot_receipt
    semantic = snapshot_evaluation.semantic_result
    semantic_maps = (
        semantic.maps
        if semantic is not None
        and semantic.status is PwnRuntimeSnapshotV1Status.CAPTURED
        else None
    )
    maps_sha256 = (
        semantic_maps.sha256
        if semantic_maps is not None
        else _EMPTY_SHA256
    )
    maps_size = (
        len(semantic_maps.data) if semantic_maps is not None else 0
    )
    maps_lines = (
        semantic_maps.line_count if semantic_maps is not None else 0
    )
    upstream = PwnDisclosureUpstreamBinding(
        crash_recipe_sha256=crash_recipe.recipe_sha256,
        crash_evaluation_sha256=crash_evaluation.evidence_sha256,
        runtime_snapshot_recipe_sha256=snapshot_recipe.recipe_sha256,
        runtime_snapshot_evaluation_sha256=(
            snapshot_evaluation.evidence_sha256
        ),
        trusted_receipt_expectation_sha256=(
            trusted_receipt_expectation.evidence_sha256
        ),
        parent_crash_recipe_sha256=(
            snapshot_recipe.parent_crash_recipe_sha256
        ),
        parent_crash_evaluation_sha256=(
            snapshot_recipe.parent_crash_evaluation_sha256
        ),
        positive_receipts=positive,
        runtime_snapshot_receipt=snapshot,
        expected_payload_sha256=crash_recipe.payload_sha256,
        expected_payload_size_bytes=crash_recipe.payload_size_bytes,
        expected_maps_sha256=maps_sha256,
        expected_maps_size_bytes=maps_size,
        expected_maps_line_count=maps_lines,
    )
    return PwnDisclosureResultBinding(
        upstream=upstream,
        payload=PwnDisclosureArtifactReference(
            artifact_id=crash_recipe.payload_artifact_id,
            sha256=crash_recipe.payload_sha256,
            size_bytes=crash_recipe.payload_size_bytes,
        ),
        crash_stderr=tuple(item.stderr for item in positive),
        runtime_stderr=snapshot.stderr,
        maps=snapshot.stdout,
    )


def _crash_receipt_valid(
    recipe: PwnCrashRecipe,
    evaluation: PwnCrashGateEvaluation,
    receipt: PwnCrashReceiptMetadata,
    *,
    ordinal: int,
) -> bool:
    semantic = evaluation.semantic_evaluation
    if semantic is None or len(semantic.observations) < ordinal:
        return False
    observation = semantic.observations[ordinal - 1]
    observation_bytes = pwn_crash_v1_canonical_json_bytes(
        observation.to_dict()
    )
    expected_attestation = PwnCrashCapabilityAttestation(
        image_digest=recipe.image_digest,
        recipe_sha256=recipe.recipe_sha256,
    ).evidence_sha256
    return (
        receipt.ordinal == ordinal
        and observation.ordinal == ordinal
        and observation.phase == "positive"
        and receipt.outcome == "succeeded"
        and receipt.exit_code == 0
        and receipt.timed_out is False
        and receipt.clean_workspace is True
        and receipt.one_shot is PWN_CRASH_ONE_SHOT
        and receipt.sandbox_method == PWN_CRASH_SANDBOX_METHOD
        and receipt.network == PWN_CRASH_NETWORK_POLICY
        and receipt.configuration_epoch == recipe.configuration_epoch
        and receipt.image_digest == recipe.image_digest
        and receipt.recipe_sha256 == recipe.recipe_sha256
        and receipt.producer_capability_name
        == PWN_CRASH_PRODUCER_CAPABILITY_NAME
        and receipt.producer_file_sha256
        == recipe.producer_file_sha256
        == PWN_CRASH_PRODUCER_FILE_SHA256
        and receipt.capability_attestation_sha256
        == expected_attestation
        and receipt.stdout_artifact_capture_placeholder is False
        and receipt.stderr_artifact_capture_placeholder is False
        and receipt.stdout_capture_complete is True
        and receipt.stdout_truncation_known is True
        and receipt.stdout_truncated is False
        and receipt.stdout_error is None
        and receipt.stream_capture_error is None
        and receipt.orchestration_error is None
        and receipt.durable_stdout_artifact_complete is True
        and receipt.stdout_artifact_size_bytes
        == len(observation_bytes)
        and receipt.stdout_drained_bytes == len(observation_bytes)
        and receipt.stdout_stored_bytes == len(observation_bytes)
        and receipt.stdout_artifact_sha256
        == hashlib.sha256(observation_bytes).hexdigest()
    )


def _snapshot_receipt_valid(
    recipe: PwnRuntimeSnapshotRecipe,
    evaluation: PwnRuntimeSnapshotGateEvaluation,
    receipt: PwnRuntimeSnapshotReceiptMetadata,
) -> bool:
    semantic = evaluation.semantic_result
    if semantic is None:
        return False
    semantic_bytes = semantic.canonical_bytes()
    expected_attestation = PwnRuntimeSnapshotCapabilityAttestation(
        image_digest=recipe.image_digest,
        recipe_sha256=recipe.recipe_sha256,
    ).evidence_sha256
    return (
        receipt.outcome == "succeeded"
        and receipt.exit_code == 0
        and receipt.timed_out is False
        and receipt.clean_workspace is True
        and receipt.one_shot is PWN_RUNTIME_SNAPSHOT_ONE_SHOT
        and receipt.sandbox_method
        == PWN_RUNTIME_SNAPSHOT_SANDBOX_METHOD
        and receipt.network == PWN_RUNTIME_SNAPSHOT_NETWORK_POLICY
        and receipt.configuration_epoch == recipe.configuration_epoch
        and receipt.image_digest == recipe.image_digest
        and receipt.recipe_sha256 == recipe.recipe_sha256
        and receipt.producer_capability_name
        == PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME
        and receipt.producer_file_sha256
        == recipe.producer_file_sha256
        == PWN_RUNTIME_SNAPSHOT_PRODUCER_FILE_SHA256
        and receipt.capability_attestation_sha256
        == expected_attestation
        and receipt.stderr_capture_placeholder is False
        and receipt.stdout_capture_complete is True
        and receipt.stdout_truncation_known is True
        and receipt.stdout_truncated is False
        and receipt.stdout_error is None
        and receipt.stream_capture_error is None
        and receipt.orchestration_error is None
        and receipt.durable_stdout_artifact_complete is True
        and receipt.stdout_artifact_size_bytes == len(semantic_bytes)
        and receipt.stdout_drained_bytes == len(semantic_bytes)
        and receipt.stdout_stored_bytes == len(semantic_bytes)
        and receipt.stdout_artifact_sha256
        == hashlib.sha256(semantic_bytes).hexdigest()
    )


def _receipt_identities_valid(
    binding: PwnDisclosureUpstreamBinding,
) -> bool:
    if tuple(
        item.ordinal for item in binding.positive_receipts
    ) != tuple(
        range(1, PWN_DISCLOSURE_POSITIVE_CRASH_REPLAYS + 1)
    ):
        return False
    receipts = (
        *binding.positive_receipts,
        binding.runtime_snapshot_receipt,
    )
    for attribute in (
        "receipt_id",
        "run_id",
        "receipt_sha256",
        "request_sha256",
        "execution_contract_sha256",
    ):
        values = [getattr(item, attribute) for item in receipts]
        if len(set(values)) != len(values):
            return False
    artifact_ids = [
        stream.artifact_id
        for receipt in receipts
        for stream in (receipt.stdout, receipt.stderr)
    ]
    return len(set(artifact_ids)) == len(artifact_ids)


def _cross_gate_binding_valid(
    crash_recipe: PwnCrashRecipe,
    crash_evaluation: PwnCrashGateEvaluation,
    snapshot_recipe: PwnRuntimeSnapshotRecipe,
    snapshot_evaluation: PwnRuntimeSnapshotGateEvaluation,
) -> bool:
    crash_semantic = crash_evaluation.semantic_evaluation
    snapshot_semantic = snapshot_evaluation.semantic_result
    if crash_semantic is None or snapshot_semantic is None:
        return False
    signal_counts = crash_semantic.positive_signal_counts
    maximum = max((count for _signal, count in signal_counts), default=0)
    expected_signals = tuple(
        signal
        for signal, count in signal_counts
        if count == maximum and count >= 2
    )
    return (
        crash_semantic.recipe_sha256 == crash_recipe.recipe_sha256
        and crash_semantic.source_manifest_sha256
        == crash_recipe.source_manifest_sha256
        and crash_semantic.source_sha256 == crash_recipe.source_sha256
        and crash_semantic.source_size_bytes
        == crash_recipe.source_size_bytes
        and crash_semantic.poc_sha256 == crash_recipe.payload_sha256
        and crash_semantic.poc_size_bytes
        == crash_recipe.payload_size_bytes
        and snapshot_recipe.parent_experiment_id
        == crash_recipe.experiment_id
        and snapshot_recipe.primary_elf_locator
        == crash_recipe.primary_elf_locator
        and snapshot_recipe.source_manifest_sha256
        == crash_recipe.source_manifest_sha256
        and snapshot_recipe.source_sha256
        == crash_recipe.source_sha256
        and snapshot_recipe.source_size_bytes
        == crash_recipe.source_size_bytes
        and snapshot_recipe.payload_artifact_id
        == crash_recipe.payload_artifact_id
        and snapshot_recipe.payload_source_run_id
        == crash_recipe.payload_source_run_id
        and snapshot_recipe.payload_artifact_locator
        == crash_recipe.payload_artifact_locator
        and snapshot_recipe.payload_sha256
        == crash_recipe.payload_sha256
        and snapshot_recipe.payload_size_bytes
        == crash_recipe.payload_size_bytes
        and snapshot_recipe.configuration_epoch
        == crash_recipe.configuration_epoch
        and snapshot_recipe.image_reference
        == crash_recipe.image_reference
        and snapshot_recipe.image_digest == crash_recipe.image_digest
        and snapshot_recipe.parent_crash_recipe_sha256
        == crash_recipe.recipe_sha256
        and snapshot_recipe.parent_crash_evaluation_sha256
        == crash_evaluation.evidence_sha256
        and expected_signals == (snapshot_recipe.expected_signal_number,)
        and snapshot_semantic.source_manifest_sha256
        == snapshot_recipe.source_manifest_sha256
        and snapshot_semantic.source_sha256
        == snapshot_recipe.source_sha256
        and snapshot_semantic.source_size_bytes
        == snapshot_recipe.source_size_bytes
        and snapshot_semantic.payload_sha256
        == snapshot_recipe.payload_sha256
        and snapshot_semantic.payload_size_bytes
        == snapshot_recipe.payload_size_bytes
        and snapshot_semantic.parent_crash_recipe_sha256
        == snapshot_recipe.parent_crash_recipe_sha256
        and snapshot_semantic.parent_crash_evaluation_sha256
        == snapshot_recipe.parent_crash_evaluation_sha256
        and snapshot_semantic.expected_signal_number
        == snapshot_recipe.expected_signal_number
        and snapshot_semantic.snapshot_recipe_sha256
        == snapshot_recipe.recipe_sha256
    )


def evaluate_pwn_disclosure(
    *,
    crash_recipe: PwnCrashRecipe,
    crash_evaluation: PwnCrashGateEvaluation,
    positive_crash_receipts: tuple[PwnCrashReceiptMetadata, ...],
    snapshot_recipe: PwnRuntimeSnapshotRecipe,
    snapshot_evaluation: PwnRuntimeSnapshotGateEvaluation,
    snapshot_receipt: PwnRuntimeSnapshotReceiptMetadata,
    trusted_receipt_expectation: (
        PwnDisclosureTrustedReceiptExpectation
    ),
    payload: bytes,
    positive_crash_stderr: tuple[bytes, ...],
    runtime_stderr: bytes,
) -> PwnDisclosureResult:
    """Evaluate four replay streams bound to both canonical prior gates.

    ``positive_crash_stderr`` must be an exact three-item tuple in replay
    order. ``runtime_stderr`` is the snapshot receipt's exact stderr bytes.
    Maps are accepted only from the CAPTURED snapshot semantic result.
    """

    if (
        type(crash_recipe) is not PwnCrashRecipe
        or type(crash_evaluation) is not PwnCrashGateEvaluation
        or type(positive_crash_receipts) is not tuple
        or len(positive_crash_receipts)
        != PWN_DISCLOSURE_POSITIVE_CRASH_REPLAYS
        or any(
            type(item) is not PwnCrashReceiptMetadata
            for item in positive_crash_receipts
        )
        or type(snapshot_recipe) is not PwnRuntimeSnapshotRecipe
        or type(snapshot_evaluation)
        is not PwnRuntimeSnapshotGateEvaluation
        or type(snapshot_receipt)
        is not PwnRuntimeSnapshotReceiptMetadata
        or type(trusted_receipt_expectation)
        is not PwnDisclosureTrustedReceiptExpectation
        or type(payload) is not bytes
        or type(positive_crash_stderr) is not tuple
        or len(positive_crash_stderr)
        != PWN_DISCLOSURE_POSITIVE_CRASH_REPLAYS
        or any(
            type(item) is not bytes
            for item in positive_crash_stderr
        )
        or type(runtime_stderr) is not bytes
    ):
        raise TypeError("exact Pwn disclosure input types are required")
    _require_current_contract_fingerprint()

    _reconstruct_typed_provenance(
        crash_recipe=crash_recipe,
        crash_evaluation=crash_evaluation,
        positive_crash_receipts=positive_crash_receipts,
        snapshot_recipe=snapshot_recipe,
        snapshot_evaluation=snapshot_evaluation,
        snapshot_receipt=snapshot_receipt,
        trusted_receipt_expectation=trusted_receipt_expectation,
    )
    binding = _result_binding(
        crash_recipe=crash_recipe,
        crash_evaluation=crash_evaluation,
        snapshot_recipe=snapshot_recipe,
        snapshot_evaluation=snapshot_evaluation,
        trusted_receipt_expectation=trusted_receipt_expectation,
    )
    try:
        supplied_positive_receipts = tuple(
            _crash_receipt_binding(item)
            for item in positive_crash_receipts
        )
        supplied_snapshot_receipt = _snapshot_receipt_binding(
            snapshot_receipt
        )
    except PwnDisclosureError:
        return _unverifiable("receipt_binding_mismatch", binding)
    if (
        supplied_positive_receipts
        != trusted_receipt_expectation.positive_receipts
        or supplied_snapshot_receipt
        != trusted_receipt_expectation.runtime_snapshot_receipt
        or binding.upstream.trusted_receipt_expectation_sha256
        != trusted_receipt_expectation.evidence_sha256
    ):
        return _unverifiable("receipt_binding_mismatch", binding)
    if (
        crash_evaluation.verdict is not PwnCrashV1Verdict.CONFIRMED
        or not crash_evaluation.passed
        or crash_evaluation.semantic_evaluation is None
    ):
        return _unverifiable("crash_gate_not_confirmed", binding)
    if (
        snapshot_evaluation.status
        is not PwnRuntimeSnapshotV1Status.CAPTURED
        or not snapshot_evaluation.captured
        or snapshot_evaluation.semantic_result is None
        or snapshot_evaluation.semantic_result.maps is None
    ):
        return _unverifiable("snapshot_gate_not_captured", binding)
    if not _cross_gate_binding_valid(
        crash_recipe,
        crash_evaluation,
        snapshot_recipe,
        snapshot_evaluation,
    ):
        return _unverifiable("provenance_binding_mismatch", binding)
    if not _receipt_identities_valid(binding.upstream) or any(
        not _crash_receipt_valid(
            crash_recipe,
            crash_evaluation,
            receipt,
            ordinal=ordinal,
        )
        for ordinal, receipt in enumerate(
            positive_crash_receipts,
            start=1,
        )
    ) or not _snapshot_receipt_valid(
        snapshot_recipe,
        snapshot_evaluation,
        snapshot_receipt,
    ):
        return _unverifiable("receipt_binding_mismatch", binding)

    maps = snapshot_evaluation.semantic_result.maps
    assert maps is not None
    evidence_limits = (
        (
            payload,
            binding.payload,
            PWN_DISCLOSURE_MAX_PAYLOAD_BYTES,
        ),
        *(
            (
                item,
                binding.crash_stderr[index],
                PWN_DISCLOSURE_MAX_STREAM_BYTES,
            )
            for index, item in enumerate(positive_crash_stderr)
        ),
        (
            runtime_stderr,
            binding.runtime_stderr,
            PWN_DISCLOSURE_MAX_STREAM_BYTES,
        ),
    )
    for data, reference, maximum in evidence_limits:
        problem = _artifact_problem(
            data,
            reference,
            maximum_bytes=maximum,
        )
        if problem is not None:
            return _unverifiable(problem, binding)

    if (
        hashlib.sha256(payload).hexdigest()
        != crash_recipe.payload_sha256
        or len(payload) != crash_recipe.payload_size_bytes
    ):
        return _unverifiable("artifact_binding_mismatch", binding)
    if (
        maps.sha256 != binding.upstream.expected_maps_sha256
        or len(maps.data) != binding.upstream.expected_maps_size_bytes
        or maps.line_count
        != binding.upstream.expected_maps_line_count
    ):
        return _unverifiable("maps_binding_mismatch", binding)
    map_lines = maps.data[:-1].split(b"\n")
    if (
        len(maps.data) > PWN_DISCLOSURE_MAX_MAPS_BYTES
        or maps.line_count > PWN_DISCLOSURE_MAX_MAP_LINES
        or any(
            len(line) > PWN_DISCLOSURE_MAX_MAP_LINE_BYTES
            for line in map_lines
        )
    ):
        return _unverifiable("maps_limit_exceeded", binding)
    try:
        ranges = parse_pwn_disclosure_maps(maps.data)
    except PwnDisclosureError:
        return _unverifiable("malformed_maps", binding)

    streams = positive_crash_stderr + (runtime_stderr,)
    try:
        extracted = tuple(_extract_tokens(item) for item in streams)
    except PwnDisclosureError:
        return _unverifiable("candidate_limit_exceeded", binding)
    shapes = set(extracted[0])
    for replay in extracted[1:]:
        shapes.intersection_update(replay)
    ordered_shapes = sorted(shapes)
    if len(ordered_shapes) > PWN_DISCLOSURE_MAX_CANDIDATES:
        return _unverifiable("candidate_limit_exceeded", binding)

    candidates: list[PwnDisclosureCandidate] = []
    for shape in ordered_shapes:
        tokens = tuple(replay[shape] for replay in extracted)
        final = tokens[-1]
        mapped = _find_range(ranges, final.value)
        commitments = tuple(
            hashlib.sha256(token.raw.lower()).hexdigest()
            for token in tokens
        )
        candidates.append(
            PwnDisclosureCandidate(
                byte_offset=shape[0],
                hex_width=shape[1],
                replay_value_sha256=commitments,
                distinct_value_count=len(
                    {token.value for token in tokens}
                ),
                final_value_sha256=commitments[-1],
                mapped_range=(
                    None
                    if mapped is None
                    else PwnDisclosureMapCommitment(
                        line_index=mapped.line_index,
                        line_sha256=mapped.line_sha256,
                    )
                ),
                payload_derived=_payload_contains(
                    payload,
                    tokens,
                ),
            )
        )
    candidate_tuple = tuple(candidates)
    if any(
        item.usable and item.distinct_value_count >= 2
        for item in candidate_tuple
    ):
        return PwnDisclosureResult(
            status=PwnDisclosureStatus.DYNAMIC_POINTER_OBSERVED,
            reason_code="dynamic_pointer_observed",
            binding=binding,
            candidates=candidate_tuple,
        )
    if any(
        item.usable and item.distinct_value_count == 1
        for item in candidate_tuple
    ):
        return PwnDisclosureResult(
            status=PwnDisclosureStatus.MAPPED_POINTER_OBSERVED,
            reason_code="mapped_pointer_observed",
            binding=binding,
            candidates=candidate_tuple,
        )
    if not candidate_tuple:
        reason = "no_common_pointer_shape"
    elif any(
        item.mapped_range is not None and item.payload_derived
        for item in candidate_tuple
    ):
        reason = "payload_echo_only"
    else:
        reason = "common_pointer_unmapped"
    return PwnDisclosureResult(
        status=PwnDisclosureStatus.UNRESOLVED,
        reason_code=reason,
        binding=binding,
        candidates=candidate_tuple,
    )


__all__ = [
    "PWN_DISCLOSURE_CONTRACT_FINGERPRINT",
    "PWN_DISCLOSURE_CONTRACT_ID",
    "PWN_DISCLOSURE_CONTRACT_VERSION",
    "PWN_DISCLOSURE_MAX_CANDIDATES",
    "PWN_DISCLOSURE_MAX_MAPS_BYTES",
    "PWN_DISCLOSURE_MAX_MAP_LINES",
    "PWN_DISCLOSURE_MAX_STREAM_BYTES",
    "PWN_DISCLOSURE_POSITIVE_CRASH_REPLAYS",
    "PWN_DISCLOSURE_SCHEMA_VERSION",
    "PwnDisclosureArtifactReference",
    "PwnDisclosureCandidate",
    "PwnDisclosureError",
    "PwnDisclosureMapCommitment",
    "PwnDisclosureMapRange",
    "PwnDisclosureResult",
    "PwnDisclosureResultBinding",
    "PwnDisclosureReceiptBinding",
    "PwnDisclosureStatus",
    "PwnDisclosureTrustedReceiptExpectation",
    "PwnDisclosureUpstreamBinding",
    "build_pwn_disclosure_trusted_receipt_expectation",
    "evaluate_pwn_disclosure",
    "parse_pwn_disclosure_maps",
    "parse_pwn_disclosure_result",
    "pwn_disclosure_canonical_json_bytes",
    "pwn_disclosure_contract_descriptor",
    "pwn_disclosure_result_sha256",
    "validate_pwn_disclosure_result",
]
