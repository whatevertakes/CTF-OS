"""Deterministic, raw-free Pwn runtime-address disclosure proof.

``pwn_disclosure`` deliberately stops at a diagnostic observation.  This
module promotes one such observation to the narrower ``leak_proven`` claim
only after three additional clean, networkless runtime-snapshot executions.
The first two executions use byte-identical derived control input and must
show independent runtime base/value variation.  The third changes exactly
one declared nonce window.  A pointer token must remain at the disclosure's
byte locus and width, be absent from the exact input, fall inside a mapping
captured by the same execution, and retain one map-relative offset while the
mapped base and pointer value vary.

The evaluator never executes a target and never mutates challenge state.
Persisted plans and results contain hashes, artifact identities, offsets, and
counts only.  They never contain literal payload bytes, literal nonce bytes,
output, maps, absolute addresses, or map-relative offsets.  Deterministic
nonce bytes are reproducible from the source inputs and are not confidential.
A positive result proves only that the target disclosed a mapped runtime
address through the observed output locus under this differential recipe. It
does not prove an exploitation primitive, an exploit, a flag, proof
satisfaction, stage advancement, or submission authority.

The engine/store boundary remains part of the trust model: it must persist
the preissued expectation before starting any replay and supply receipts from
the challenge sandbox rather than rebuilding an expectation from selected
outputs.  Each preissued request and execution-contract hash must commit to
the exact canonical request document already persisted by the engine; this
pure evaluator cannot establish that temporal fact from a hash label alone.
It can reject direct encodings and use a same-input control, but it is not a
causal taint tracker and does not claim to exclude every target-computed
transformation of input bytes.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum

from ctf_os.contracts.pwn_leak_requirement_v1 import (
    PwnLeakRequirementV1ElfProfile,
    PwnLeakRequirementV1Result,
    PwnLeakRequirementV1Strategy,
    classify_pwn_leak_requirement_v1,
)
from ctf_os.contracts.pwn_runtime_snapshot_v1 import (
    PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_FINGERPRINT,
    PWN_RUNTIME_SNAPSHOT_V1_MAX_DOCUMENT_BYTES,
    PWN_RUNTIME_SNAPSHOT_V1_MAX_MAPS_BYTES,
    PWN_RUNTIME_SNAPSHOT_V1_MAX_PAYLOAD_BYTES,
    PWN_RUNTIME_SNAPSHOT_V1_MAX_SOURCE_BYTES,
)
from ctf_os.engine.pwn_disclosure import (
    PWN_DISCLOSURE_CONTRACT_FINGERPRINT,
    PWN_DISCLOSURE_MAX_MAP_LINE_BYTES,
    PWN_DISCLOSURE_MAX_MAP_LINES,
    PWN_DISCLOSURE_MAX_STREAM_BYTES,
    PwnDisclosureCandidate,
    PwnDisclosureResult,
    PwnDisclosureStatus,
)
from ctf_os.engine.pwn_runtime_snapshot import (
    PWN_RUNTIME_SNAPSHOT_NETWORK_POLICY,
    PWN_RUNTIME_SNAPSHOT_ONE_SHOT,
    PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME,
    PWN_RUNTIME_SNAPSHOT_PRODUCER_FILE_SHA256,
    PWN_RUNTIME_SNAPSHOT_SANDBOX_METHOD,
    PwnRuntimeSnapshotCapabilityAttestation,
    PwnRuntimeSnapshotGateEvaluation,
    PwnRuntimeSnapshotReceiptMetadata,
    PwnRuntimeSnapshotRecipe,
    evaluate_pwn_runtime_snapshot_gate,
)


PWN_LEAK_SCHEMA_VERSION = 1
PWN_LEAK_CONTRACT_ID = "ctfos.pwn.leak_proof"
PWN_LEAK_CONTRACT_VERSION = 1
PWN_LEAK_REPLAY_COUNT = 3
PWN_LEAK_MIN_NONCE_BYTES = 8
PWN_LEAK_MAX_NONCE_BYTES = 32
PWN_LEAK_MAX_DERIVATION_ATTEMPTS = 256
PWN_LEAK_MAX_RESULT_BYTES = 128 * 1024

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,511}$")
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
_U64_MAX = (1 << 64) - 1

_AUTHORITIES_FALSE = {
    "address_resolution_proven": False,
    "auto_submit_authorized": False,
    "exploit_proven": False,
    "flag_proven": False,
    "global_leak_not_applicable_proven": False,
    "primitive_proven": False,
    "proof_satisfied": False,
    "runtime_address_disclosure_proven": False,
    "stage_advance_authorized": False,
}
_UNVERIFIABLE_REASONS = frozenset(
    {
        "disclosure_not_eligible",
        "input_variant_mismatch",
        "leaked_value_not_varied",
        "mapping_identity_changed",
        "maps_invalid",
        "paired_control_runtime_state_not_varied",
        "plan_binding_mismatch",
        "pointer_payload_derived",
        "pointer_unmapped",
        "relative_offset_changed",
        "replay_gate_changed",
        "replay_identity_reused",
        "replay_not_captured",
        "replay_receipt_binding_mismatch",
        "replay_recipe_binding_mismatch",
        "runtime_base_not_varied",
        "stable_locus_missing",
        "trusted_replay_expectation_mismatch",
    }
)
_PROVEN_REASON = "runtime_address_disclosure_reproduced"
_PLAN_KEYS = frozenset(
    {
        "binding",
        "contract",
        "derivation_algorithm",
        "recipe_sha256",
        "replays",
        "schema_version",
    }
)
_PLAN_BINDING_KEYS = frozenset(
    {
        "baseline_payload_artifact_id",
        "baseline_payload_sha256",
        "baseline_payload_size_bytes",
        "baseline_snapshot_recipe_sha256",
        "candidate_byte_offset",
        "candidate_hex_width",
        "candidate_sha256",
        "derivation_seed_sha256",
        "disclosure_result_sha256",
        "nonce_offset",
        "nonce_width_bytes",
        "source_manifest_sha256",
        "source_sha256",
        "source_size_bytes",
    }
)
_PLAN_REPLAY_KEYS = frozenset(
    {
        "input_sha256",
        "input_size_bytes",
        "nonce_sha256",
        "ordinal",
    }
)
_TRUST_BINDING_KEYS = frozenset(
    {
        "capability_attestation_artifact_id",
        "execution_contract_sha256",
        "input_artifact_id",
        "input_locator_sha256",
        "input_sha256",
        "input_size_bytes",
        "ordinal",
        "output_artifact_id",
        "receipt_id",
        "recipe_sha256",
        "request_sha256",
        "run_id",
        "stdout_artifact_id",
    }
)
_TRUST_EXPECTATION_KEYS = frozenset(
    {"preexisting_artifact_ids", "replays", "schema_version"}
)
_PREISSUED_IDENTITY_KEYS = frozenset(
    {
        "capability_attestation_artifact_id",
        "execution_contract_sha256",
        "ordinal",
        "output_artifact_id",
        "receipt_id",
        "request_sha256",
        "run_id",
        "stdout_artifact_id",
    }
)
_CONTRACT_KEYS = frozenset({"fingerprint", "id", "version"})
_COMMITMENT_KEYS = frozenset(
    {
        "capability_attestation_artifact_id",
        "capability_attestation_sha256",
        "evaluation_sha256",
        "execution_contract_sha256",
        "input_artifact_id",
        "input_sha256",
        "input_size_bytes",
        "map_base_sha256",
        "map_identity_sha256",
        "map_line_index",
        "map_line_sha256",
        "nonce_sha256",
        "observed_value_sha256",
        "ordinal",
        "output_artifact_id",
        "output_sha256",
        "output_size_bytes",
        "receipt_id",
        "receipt_sha256",
        "recipe_sha256",
        "relative_offset_sha256",
        "request_sha256",
        "run_id",
        "stdout_artifact_id",
        "stdout_sha256",
        "stdout_size_bytes",
    }
)
_RESULT_KEYS = frozenset(
    {
        "authorities",
        "binding",
        "contract",
        "reason_code",
        "replays",
        "schema_version",
        "status",
        "summary",
    }
)
_RESULT_BINDING_KEYS = frozenset(
    {
        "baseline_payload_sha256",
        "baseline_payload_size_bytes",
        "candidate_byte_offset",
        "candidate_hex_width",
        "disclosure_result_sha256",
        "plan_recipe_sha256",
        "source_manifest_sha256",
        "source_sha256",
        "source_size_bytes",
        "trusted_replay_expectation_sha256",
    }
)
_SUMMARY_KEYS = frozenset(
    {
        "distinct_mapping_base_count",
        "distinct_runtime_value_count",
        "stable_map_identity_sha256",
        "stable_relative_offset_sha256",
    }
)
_DERIVATION_ALGORITHM = (
    "sha256-domain-seed-ordinal-attempt;replace-exact-nonce-window-v1"
)


def _canonical_json_bytes(value: object) -> bytes:
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


def pwn_leak_contract_descriptor() -> dict[str, object]:
    """Return the immutable semantic descriptor for this proof gate."""

    return {
        "authority": {
            **_AUTHORITIES_FALSE,
            "leak_proven": "true-only-after-all-three-replays-pass",
        },
        "candidate_anchor": (
            "one-usable-pwn-disclosure-v1-candidate-by-exact-offset-width"
        ),
        "contract_id": PWN_LEAK_CONTRACT_ID,
        "contract_version": PWN_LEAK_CONTRACT_VERSION,
        "input_variation": {
            "count": PWN_LEAK_REPLAY_COUNT,
            "derivation": _DERIVATION_ALGORITHM,
            "maximum_nonce_bytes": PWN_LEAK_MAX_NONCE_BYTES,
            "minimum_nonce_bytes": PWN_LEAK_MIN_NONCE_BYTES,
            "mutation": (
                "replays-one-and-two-use-the-same-derived-control;"
                "replay-three-uses-one-distinct-derived-variant;"
                "only-the-declared-contiguous-nonce-window-changes"
            ),
        },
        "mapping_consistency": {
            "base_variation": "at-least-two-distinct-bases",
            "identity": (
                "same-line-index-permissions-file-offset-and-path-hash"
            ),
            "pointer_variation": "at-least-two-distinct-values",
            "relative_offset": "exactly-equal-across-all-replays",
        },
        "persistence": {
            "absolute_addresses": False,
            "map_relative_offsets": False,
            "maps": False,
            "nonce_bytes": False,
            "nonce_confidentiality": (
                "not-claimed;literal-bytes-omitted-but-deterministic"
            ),
            "output": False,
            "payload_bytes": False,
            "result_max_bytes": PWN_LEAK_MAX_RESULT_BYTES,
        },
        "replay": {
            "artifact_identity_scope": (
                "all-preexisting-and-replay-artifact-identities"
            ),
            "clean_workspace": True,
            "count": PWN_LEAK_REPLAY_COUNT,
            "network": PWN_RUNTIME_SNAPSHOT_NETWORK_POLICY,
            "one_shot": PWN_RUNTIME_SNAPSHOT_ONE_SHOT,
            "producer_capability": (
                PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME
            ),
            "producer_file_sha256": (
                PWN_RUNTIME_SNAPSHOT_PRODUCER_FILE_SHA256
            ),
            "sandbox_method": PWN_RUNTIME_SNAPSHOT_SANDBOX_METHOD,
            "trust_anchor": (
                "engine-derived-canonical-prior-state-expectation;"
                "never-derived-inside-evaluator"
            ),
        },
        "schema_version": PWN_LEAK_SCHEMA_VERSION,
        "upstream_fingerprints": {
            "pwn_disclosure_v1": PWN_DISCLOSURE_CONTRACT_FINGERPRINT,
            "pwn_runtime_snapshot_v1": (
                PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_FINGERPRINT
            ),
        },
        "verdicts": ["PROVEN", "UNVERIFIABLE"],
    }


PWN_LEAK_CONTRACT_FINGERPRINT = hashlib.sha256(
    _canonical_json_bytes(pwn_leak_contract_descriptor())
).hexdigest()


def _require_current_contract_fingerprint() -> None:
    observed = hashlib.sha256(
        _canonical_json_bytes(pwn_leak_contract_descriptor())
    ).hexdigest()
    if observed != PWN_LEAK_CONTRACT_FINGERPRINT:
        raise ValueError("Pwn leak contract dependency drift")


def _sha256(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _identifier(value: object) -> bool:
    return type(value) is str and _IDENTIFIER.fullmatch(value) is not None


def _hash_u64(value: int) -> str:
    return hashlib.sha256(value.to_bytes(8, "little")).hexdigest()


def _candidate_sha256(candidate: PwnDisclosureCandidate) -> str:
    return hashlib.sha256(
        _canonical_json_bytes(candidate.to_dict())
    ).hexdigest()


def pwn_leak_child_experiment_id(
    baseline_experiment_id: str,
) -> str:
    """Return the only leak-proof child id for one runtime snapshot."""

    if not _identifier(baseline_experiment_id):
        raise ValueError("invalid Pwn leak baseline experiment id")
    digest = hashlib.sha256(
        baseline_experiment_id.encode("utf-8")
    ).hexdigest()
    return f"E-pwn-leak-v1-{digest}"


class PwnLeakStatus(str, Enum):
    PROVEN = "PROVEN"
    UNVERIFIABLE = "UNVERIFIABLE"


@dataclass(frozen=True, slots=True)
class PwnLeakPlan:
    """Raw-bearing in-memory plan with a raw-free persisted projection."""

    source_manifest_sha256: str
    source_sha256: str
    source_size_bytes: int
    baseline_snapshot_recipe_sha256: str
    baseline_payload_artifact_id: str
    baseline_payload_sha256: str
    baseline_payload_size_bytes: int
    disclosure_result_sha256: str
    candidate_byte_offset: int
    candidate_hex_width: int
    candidate_sha256: str
    nonce_offset: int
    nonce_width_bytes: int
    derivation_seed_sha256: str
    nonces: tuple[bytes, ...] = field(repr=False)
    payloads: tuple[bytes, ...] = field(repr=False)

    def __post_init__(self) -> None:
        hashes = (
            self.source_manifest_sha256,
            self.source_sha256,
            self.baseline_snapshot_recipe_sha256,
            self.baseline_payload_sha256,
            self.disclosure_result_sha256,
            self.candidate_sha256,
            self.derivation_seed_sha256,
        )
        if (
            any(not _sha256(item) for item in hashes)
            or not _identifier(self.baseline_payload_artifact_id)
            or type(self.source_size_bytes) is not int
            or not 1
            <= self.source_size_bytes
            <= PWN_RUNTIME_SNAPSHOT_V1_MAX_SOURCE_BYTES
            or type(self.baseline_payload_size_bytes) is not int
            or not 1
            <= self.baseline_payload_size_bytes
            <= PWN_RUNTIME_SNAPSHOT_V1_MAX_PAYLOAD_BYTES
            or type(self.candidate_byte_offset) is not int
            or self.candidate_byte_offset < 0
            or type(self.candidate_hex_width) is not int
            or not 6 <= self.candidate_hex_width <= 16
            or type(self.nonce_offset) is not int
            or self.nonce_offset < 0
            or type(self.nonce_width_bytes) is not int
            or not PWN_LEAK_MIN_NONCE_BYTES
            <= self.nonce_width_bytes
            <= PWN_LEAK_MAX_NONCE_BYTES
            or self.nonce_offset + self.nonce_width_bytes
            > self.baseline_payload_size_bytes
            or type(self.nonces) is not tuple
            or len(self.nonces) != PWN_LEAK_REPLAY_COUNT
            or any(
                type(item) is not bytes
                or len(item) != self.nonce_width_bytes
                for item in self.nonces
            )
            or self.nonces[0] != self.nonces[1]
            or self.nonces[2] == self.nonces[0]
            or type(self.payloads) is not tuple
            or len(self.payloads) != PWN_LEAK_REPLAY_COUNT
            or any(
                type(item) is not bytes
                or len(item) != self.baseline_payload_size_bytes
                for item in self.payloads
            )
            or self.payloads[0] != self.payloads[1]
            or self.payloads[2] == self.payloads[0]
        ):
            raise ValueError("invalid Pwn leak plan")

    def content_dict(self) -> dict[str, object]:
        return {
            "binding": {
                "baseline_payload_artifact_id": (
                    self.baseline_payload_artifact_id
                ),
                "baseline_payload_sha256": self.baseline_payload_sha256,
                "baseline_payload_size_bytes": (
                    self.baseline_payload_size_bytes
                ),
                "baseline_snapshot_recipe_sha256": (
                    self.baseline_snapshot_recipe_sha256
                ),
                "candidate_byte_offset": self.candidate_byte_offset,
                "candidate_hex_width": self.candidate_hex_width,
                "candidate_sha256": self.candidate_sha256,
                "derivation_seed_sha256": self.derivation_seed_sha256,
                "disclosure_result_sha256": (
                    self.disclosure_result_sha256
                ),
                "nonce_offset": self.nonce_offset,
                "nonce_width_bytes": self.nonce_width_bytes,
                "source_manifest_sha256": self.source_manifest_sha256,
                "source_sha256": self.source_sha256,
                "source_size_bytes": self.source_size_bytes,
            },
            "contract": {
                "fingerprint": PWN_LEAK_CONTRACT_FINGERPRINT,
                "id": PWN_LEAK_CONTRACT_ID,
                "version": PWN_LEAK_CONTRACT_VERSION,
            },
            "derivation_algorithm": _DERIVATION_ALGORITHM,
            "replays": [
                {
                    "input_sha256": hashlib.sha256(payload).hexdigest(),
                    "input_size_bytes": len(payload),
                    "nonce_sha256": hashlib.sha256(nonce).hexdigest(),
                    "ordinal": ordinal,
                }
                for ordinal, (nonce, payload) in enumerate(
                    zip(self.nonces, self.payloads, strict=True),
                    start=1,
                )
            ],
            "schema_version": PWN_LEAK_SCHEMA_VERSION,
        }

    @property
    def recipe_sha256(self) -> str:
        return hashlib.sha256(
            _canonical_json_bytes(self.content_dict())
        ).hexdigest()

    def to_dict(self) -> dict[str, object]:
        value = self.content_dict()
        value["recipe_sha256"] = self.recipe_sha256
        return value


def validate_pwn_leak_plan_document(
    value: object,
) -> dict[str, object]:
    """Validate a persisted raw-free plan without trusting its self-hash."""

    if type(value) is not dict or set(value) != _PLAN_KEYS:
        raise ValueError("invalid Pwn leak plan schema")
    binding = value.get("binding")
    contract = value.get("contract")
    replays = value.get("replays")
    if (
        type(binding) is not dict
        or set(binding) != _PLAN_BINDING_KEYS
        or type(contract) is not dict
        or set(contract) != _CONTRACT_KEYS
        or type(contract.get("version")) is not int
        or contract
        != {
            "fingerprint": PWN_LEAK_CONTRACT_FINGERPRINT,
            "id": PWN_LEAK_CONTRACT_ID,
            "version": PWN_LEAK_CONTRACT_VERSION,
        }
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != PWN_LEAK_SCHEMA_VERSION
        or value.get("derivation_algorithm") != _DERIVATION_ALGORITHM
        or type(replays) is not list
        or len(replays) != PWN_LEAK_REPLAY_COUNT
        or not _sha256(value.get("recipe_sha256"))
    ):
        raise ValueError("invalid Pwn leak plan schema")
    for field in (
        "baseline_payload_sha256",
        "baseline_snapshot_recipe_sha256",
        "candidate_sha256",
        "derivation_seed_sha256",
        "disclosure_result_sha256",
        "source_manifest_sha256",
        "source_sha256",
    ):
        if not _sha256(binding.get(field)):
            raise ValueError("invalid Pwn leak plan binding")
    size = binding.get("baseline_payload_size_bytes")
    source_size = binding.get("source_size_bytes")
    nonce_offset = binding.get("nonce_offset")
    nonce_width = binding.get("nonce_width_bytes")
    if (
        not _identifier(binding.get("baseline_payload_artifact_id"))
        or type(size) is not int
        or not 1 <= size <= PWN_RUNTIME_SNAPSHOT_V1_MAX_PAYLOAD_BYTES
        or type(source_size) is not int
        or not 1
        <= source_size
        <= PWN_RUNTIME_SNAPSHOT_V1_MAX_SOURCE_BYTES
        or type(binding.get("candidate_byte_offset")) is not int
        or binding["candidate_byte_offset"] < 0
        or type(binding.get("candidate_hex_width")) is not int
        or not 6 <= binding["candidate_hex_width"] <= 16
        or type(nonce_offset) is not int
        or nonce_offset < 0
        or type(nonce_width) is not int
        or not PWN_LEAK_MIN_NONCE_BYTES
        <= nonce_width
        <= PWN_LEAK_MAX_NONCE_BYTES
        or nonce_offset + nonce_width > size
    ):
        raise ValueError("invalid Pwn leak plan binding")
    input_hashes: list[str] = []
    nonce_hashes: list[str] = []
    for ordinal, replay in enumerate(replays, start=1):
        if (
            type(replay) is not dict
            or set(replay) != _PLAN_REPLAY_KEYS
            or type(replay.get("ordinal")) is not int
            or replay.get("ordinal") != ordinal
            or type(replay.get("input_size_bytes")) is not int
            or replay.get("input_size_bytes") != size
            or not _sha256(replay.get("input_sha256"))
            or not _sha256(replay.get("nonce_sha256"))
        ):
            raise ValueError("invalid Pwn leak plan replay")
        input_hashes.append(replay["input_sha256"])
        nonce_hashes.append(replay["nonce_sha256"])
    if (
        input_hashes[0] != input_hashes[1]
        or input_hashes[2] == input_hashes[0]
        or nonce_hashes[0] != nonce_hashes[1]
        or nonce_hashes[2] == nonce_hashes[0]
    ):
        raise ValueError("invalid Pwn leak control/variant layout")
    unsigned = dict(value)
    supplied = unsigned.pop("recipe_sha256")
    if hashlib.sha256(_canonical_json_bytes(unsigned)).hexdigest() != supplied:
        raise ValueError("Pwn leak plan recipe hash mismatch")
    return value


def _select_candidate(
    disclosure: PwnDisclosureResult,
    *,
    byte_offset: int,
    hex_width: int,
) -> PwnDisclosureCandidate:
    if (
        disclosure.status
        not in {
            PwnDisclosureStatus.DYNAMIC_POINTER_OBSERVED,
            PwnDisclosureStatus.MAPPED_POINTER_OBSERVED,
        }
        or type(byte_offset) is not int
        or type(hex_width) is not int
    ):
        raise ValueError("disclosure_not_eligible")
    matches = [
        candidate
        for candidate in disclosure.candidates
        if (
            candidate.byte_offset == byte_offset
            and candidate.hex_width == hex_width
            and candidate.usable
        )
    ]
    if len(matches) != 1:
        raise ValueError("disclosure_not_eligible")
    return matches[0]


def derive_pwn_leak_plan(
    disclosure: PwnDisclosureResult,
    baseline_snapshot_recipe: PwnRuntimeSnapshotRecipe,
    baseline_payload: bytes,
    *,
    candidate_byte_offset: int,
    candidate_hex_width: int,
    nonce_offset: int,
    nonce_width_bytes: int,
) -> PwnLeakPlan:
    """Derive three exact nonce-only payload variants."""

    if (
        type(disclosure) is not PwnDisclosureResult
        or type(baseline_snapshot_recipe)
        is not PwnRuntimeSnapshotRecipe
        or type(baseline_payload) is not bytes
    ):
        raise TypeError("exact disclosure, recipe, and payload required")
    _require_current_contract_fingerprint()
    candidate = _select_candidate(
        disclosure,
        byte_offset=candidate_byte_offset,
        hex_width=candidate_hex_width,
    )
    upstream = disclosure.binding.upstream
    recipe = baseline_snapshot_recipe
    if (
        upstream.runtime_snapshot_recipe_sha256
        != recipe.recipe_sha256
        or upstream.parent_crash_recipe_sha256
        != recipe.parent_crash_recipe_sha256
        or upstream.parent_crash_evaluation_sha256
        != recipe.parent_crash_evaluation_sha256
        or disclosure.binding.payload.artifact_id
        != recipe.payload_artifact_id
        or disclosure.binding.payload.sha256 != recipe.payload_sha256
        or disclosure.binding.payload.size_bytes
        != recipe.payload_size_bytes
        or hashlib.sha256(baseline_payload).hexdigest()
        != recipe.payload_sha256
        or len(baseline_payload) != recipe.payload_size_bytes
        or type(nonce_offset) is not int
        or nonce_offset < 0
        or type(nonce_width_bytes) is not int
        or not PWN_LEAK_MIN_NONCE_BYTES
        <= nonce_width_bytes
        <= PWN_LEAK_MAX_NONCE_BYTES
        or nonce_offset + nonce_width_bytes > len(baseline_payload)
    ):
        raise ValueError("plan_binding_mismatch")
    seed = hashlib.sha256(
        _canonical_json_bytes(
            {
                "baseline_payload_sha256": recipe.payload_sha256,
                "baseline_snapshot_recipe_sha256": recipe.recipe_sha256,
                "candidate_byte_offset": candidate.byte_offset,
                "candidate_hex_width": candidate.hex_width,
                "candidate_sha256": _candidate_sha256(candidate),
                "disclosure_result_sha256": disclosure.evidence_sha256,
                "domain": "ctfos.pwn.leak.plan.v1",
                "nonce_offset": nonce_offset,
                "nonce_width_bytes": nonce_width_bytes,
                "source_manifest_sha256": (
                    recipe.source_manifest_sha256
                ),
                "source_sha256": recipe.source_sha256,
            }
        )
    ).hexdigest()
    original_window = baseline_payload[
        nonce_offset : nonce_offset + nonce_width_bytes
    ]
    nonces: list[bytes] = []
    payloads: list[bytes] = []
    for ordinal in range(1, PWN_LEAK_REPLAY_COUNT + 1):
        if ordinal == 2:
            selected = nonces[0]
        else:
            variant_ordinal = 1 if ordinal == 1 else 2
            selected: bytes | None = None
            for attempt in range(PWN_LEAK_MAX_DERIVATION_ATTEMPTS):
                candidate_nonce = hashlib.sha256(
                    b"ctfos.pwn.leak.nonce.v1\x00"
                    + bytes.fromhex(seed)
                    + variant_ordinal.to_bytes(1, "big")
                    + attempt.to_bytes(2, "big")
                ).digest()[:nonce_width_bytes]
                if (
                    candidate_nonce != original_window
                    and candidate_nonce not in nonces
                ):
                    selected = candidate_nonce
                    break
            if selected is None:
                raise ValueError("nonce_derivation_exhausted")
        payload = (
            baseline_payload[:nonce_offset]
            + selected
            + baseline_payload[nonce_offset + nonce_width_bytes :]
        )
        nonces.append(selected)
        payloads.append(payload)
    plan = PwnLeakPlan(
        source_manifest_sha256=recipe.source_manifest_sha256,
        source_sha256=recipe.source_sha256,
        source_size_bytes=recipe.source_size_bytes,
        baseline_snapshot_recipe_sha256=recipe.recipe_sha256,
        baseline_payload_artifact_id=recipe.payload_artifact_id,
        baseline_payload_sha256=recipe.payload_sha256,
        baseline_payload_size_bytes=recipe.payload_size_bytes,
        disclosure_result_sha256=disclosure.evidence_sha256,
        candidate_byte_offset=candidate.byte_offset,
        candidate_hex_width=candidate.hex_width,
        candidate_sha256=_candidate_sha256(candidate),
        nonce_offset=nonce_offset,
        nonce_width_bytes=nonce_width_bytes,
        derivation_seed_sha256=seed,
        nonces=tuple(nonces),
        payloads=tuple(payloads),
    )
    validate_pwn_leak_plan_document(plan.to_dict())
    return plan


@dataclass(frozen=True, slots=True)
class PwnLeakPreissuedReplayIdentity:
    """IDs and request commitments issued before one sandbox execution."""

    ordinal: int
    run_id: str
    receipt_id: str
    request_sha256: str
    execution_contract_sha256: str
    capability_attestation_artifact_id: str
    stdout_artifact_id: str
    output_artifact_id: str

    def __post_init__(self) -> None:
        if (
            type(self.ordinal) is not int
            or not 1 <= self.ordinal <= PWN_LEAK_REPLAY_COUNT
            or any(
                not _sha256(getattr(self, field))
                for field in (
                    "request_sha256",
                    "execution_contract_sha256",
                )
            )
            or any(
                not _identifier(getattr(self, field))
                for field in (
                    "run_id",
                    "receipt_id",
                    "capability_attestation_artifact_id",
                    "stdout_artifact_id",
                    "output_artifact_id",
                )
            )
            or len(
                {
                    self.capability_attestation_artifact_id,
                    self.stdout_artifact_id,
                    self.output_artifact_id,
                }
            )
            != 3
        ):
            raise ValueError("invalid preissued Pwn leak identity")

    def to_dict(self) -> dict[str, object]:
        return {
            key: getattr(self, key)
            for key in sorted(_PREISSUED_IDENTITY_KEYS)
        }

    @classmethod
    def from_dict(
        cls,
        value: object,
    ) -> "PwnLeakPreissuedReplayIdentity":
        if (
            type(value) is not dict
            or set(value) != _PREISSUED_IDENTITY_KEYS
        ):
            raise ValueError("invalid preissued Pwn leak identity")
        return cls(**value)


@dataclass(frozen=True, slots=True)
class PwnLeakTrustedReplayBinding:
    """One exact recipe bound to a preissued execution identity."""

    ordinal: int
    input_artifact_id: str
    input_locator_sha256: str
    input_sha256: str
    input_size_bytes: int
    recipe_sha256: str
    run_id: str
    receipt_id: str
    request_sha256: str
    execution_contract_sha256: str
    capability_attestation_artifact_id: str
    stdout_artifact_id: str
    output_artifact_id: str

    def __post_init__(self) -> None:
        if (
            type(self.ordinal) is not int
            or not 1 <= self.ordinal <= PWN_LEAK_REPLAY_COUNT
            or any(
                not _sha256(getattr(self, field))
                for field in (
                    "input_locator_sha256",
                    "input_sha256",
                    "recipe_sha256",
                    "request_sha256",
                    "execution_contract_sha256",
                )
            )
            or any(
                not _identifier(getattr(self, field))
                for field in (
                    "input_artifact_id",
                    "run_id",
                    "receipt_id",
                    "capability_attestation_artifact_id",
                    "stdout_artifact_id",
                    "output_artifact_id",
                )
            )
            or type(self.input_size_bytes) is not int
            or not 1
            <= self.input_size_bytes
            <= PWN_RUNTIME_SNAPSHOT_V1_MAX_PAYLOAD_BYTES
        ):
            raise ValueError("invalid trusted Pwn leak replay binding")

    def to_dict(self) -> dict[str, object]:
        return {
            key: getattr(self, key) for key in sorted(_TRUST_BINDING_KEYS)
        }

    @classmethod
    def from_dict(
        cls,
        value: object,
    ) -> "PwnLeakTrustedReplayBinding":
        if type(value) is not dict or set(value) != _TRUST_BINDING_KEYS:
            raise ValueError("invalid trusted Pwn leak replay binding")
        return cls(**value)


@dataclass(frozen=True, slots=True)
class PwnLeakTrustedReplayExpectation:
    """Engine-issued trust anchor persisted before target execution.

    Build this from exact replay recipes and preissued run/request/artifact
    identities plus the sorted IDs of every artifact already in canonical
    state.  Persist it and the exact request documents in canonical engine
    state, and only then execute the three runs.  Building it after observing
    target output defeats the anti-cherry-picking boundary and is unsupported.
    """

    preexisting_artifact_ids: tuple[str, ...]
    replays: tuple[PwnLeakTrustedReplayBinding, ...]

    def __post_init__(self) -> None:
        if (
            type(self.preexisting_artifact_ids) is not tuple
            or not self.preexisting_artifact_ids
            or any(
                not _identifier(item)
                for item in self.preexisting_artifact_ids
            )
            or len(set(self.preexisting_artifact_ids))
            != len(self.preexisting_artifact_ids)
            or self.preexisting_artifact_ids
            != tuple(sorted(self.preexisting_artifact_ids))
            or type(self.replays) is not tuple
            or len(self.replays) != PWN_LEAK_REPLAY_COUNT
            or any(
                type(item) is not PwnLeakTrustedReplayBinding
                for item in self.replays
            )
            or tuple(item.ordinal for item in self.replays)
            != tuple(range(1, PWN_LEAK_REPLAY_COUNT + 1))
        ):
            raise ValueError("invalid trusted Pwn leak expectation")
        for field in (
            "input_artifact_id",
            "recipe_sha256",
            "run_id",
            "receipt_id",
            "request_sha256",
            "execution_contract_sha256",
            "capability_attestation_artifact_id",
            "stdout_artifact_id",
            "output_artifact_id",
        ):
            values = tuple(getattr(item, field) for item in self.replays)
            if len(set(values)) != PWN_LEAK_REPLAY_COUNT:
                raise ValueError("reused trusted Pwn leak identity")
        if (
            self.replays[0].input_sha256
            != self.replays[1].input_sha256
            or self.replays[2].input_sha256
            == self.replays[0].input_sha256
        ):
            raise ValueError("invalid trusted control/variant layout")
        artifact_ids = tuple(
            artifact_id
            for replay in self.replays
            for artifact_id in (
                replay.input_artifact_id,
                replay.capability_attestation_artifact_id,
                replay.stdout_artifact_id,
                replay.output_artifact_id,
            )
        )
        if (
            len(set(artifact_ids)) != len(artifact_ids)
            or not set(artifact_ids).isdisjoint(
                self.preexisting_artifact_ids
            )
        ):
            raise ValueError("trusted Pwn leak artifact identity collision")
        self.canonical_bytes()

    def to_dict(self) -> dict[str, object]:
        return {
            "preexisting_artifact_ids": list(
                self.preexisting_artifact_ids
            ),
            "replays": [item.to_dict() for item in self.replays],
            "schema_version": PWN_LEAK_SCHEMA_VERSION,
        }

    def canonical_bytes(self) -> bytes:
        payload = _canonical_json_bytes(self.to_dict())
        if len(payload) > PWN_LEAK_MAX_RESULT_BYTES:
            raise ValueError("trusted Pwn leak expectation exceeds byte limit")
        return payload

    @property
    def evidence_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    @classmethod
    def from_dict(
        cls,
        value: object,
    ) -> "PwnLeakTrustedReplayExpectation":
        if (
            type(value) is not dict
            or set(value) != _TRUST_EXPECTATION_KEYS
            or type(value.get("schema_version")) is not int
            or value.get("schema_version") != PWN_LEAK_SCHEMA_VERSION
            or type(value.get("preexisting_artifact_ids")) is not list
            or type(value.get("replays")) is not list
            or len(value["replays"]) != PWN_LEAK_REPLAY_COUNT
        ):
            raise ValueError("invalid trusted Pwn leak expectation")
        result = cls(
            preexisting_artifact_ids=tuple(
                value["preexisting_artifact_ids"]
            ),
            replays=tuple(
                PwnLeakTrustedReplayBinding.from_dict(item)
                for item in value["replays"]
            )
        )
        if value != result.to_dict():
            raise ValueError("trusted Pwn leak expectation not reconstructable")
        return result


def _trusted_replay_binding(
    recipe: PwnRuntimeSnapshotRecipe,
    identity: PwnLeakPreissuedReplayIdentity,
) -> PwnLeakTrustedReplayBinding:
    return PwnLeakTrustedReplayBinding(
        ordinal=identity.ordinal,
        input_artifact_id=recipe.payload_artifact_id,
        input_locator_sha256=hashlib.sha256(
            recipe.payload_artifact_locator.encode("utf-8")
        ).hexdigest(),
        input_sha256=recipe.payload_sha256,
        input_size_bytes=recipe.payload_size_bytes,
        recipe_sha256=recipe.recipe_sha256,
        run_id=identity.run_id,
        receipt_id=identity.receipt_id,
        request_sha256=identity.request_sha256,
        execution_contract_sha256=identity.execution_contract_sha256,
        capability_attestation_artifact_id=(
            identity.capability_attestation_artifact_id
        ),
        stdout_artifact_id=identity.stdout_artifact_id,
        output_artifact_id=identity.output_artifact_id,
    )


def build_pwn_leak_trusted_replay_expectation(
    *,
    replay_recipes: tuple[PwnRuntimeSnapshotRecipe, ...],
    preissued_identities: tuple[PwnLeakPreissuedReplayIdentity, ...],
    preexisting_artifact_ids: tuple[str, ...],
) -> PwnLeakTrustedReplayExpectation:
    """Build the canonical trust anchor before executing the target.

    The caller must derive ``preissued_identities`` from exact canonical
    request documents and persist both those documents and the returned
    expectation before starting replay one.  Hash labels alone cannot prove
    this ordering inside a pure evaluator.
    """

    if (
        type(replay_recipes) is not tuple
        or len(replay_recipes) != PWN_LEAK_REPLAY_COUNT
        or any(
            type(item) is not PwnRuntimeSnapshotRecipe
            for item in replay_recipes
        )
        or type(preissued_identities) is not tuple
        or len(preissued_identities) != PWN_LEAK_REPLAY_COUNT
        or any(
            type(item) is not PwnLeakPreissuedReplayIdentity
            for item in preissued_identities
        )
        or type(preexisting_artifact_ids) is not tuple
        or not preexisting_artifact_ids
        or any(not _identifier(item) for item in preexisting_artifact_ids)
        or len(set(preexisting_artifact_ids))
        != len(preexisting_artifact_ids)
        or tuple(item.ordinal for item in preissued_identities)
        != tuple(range(1, PWN_LEAK_REPLAY_COUNT + 1))
    ):
        raise TypeError("exact Pwn leak recipe/preissued records required")
    _require_current_contract_fingerprint()
    try:
        canonical_recipes = tuple(
            PwnRuntimeSnapshotRecipe.from_dict(item.to_dict())
            for item in replay_recipes
        )
        canonical_identities = tuple(
            PwnLeakPreissuedReplayIdentity.from_dict(item.to_dict())
            for item in preissued_identities
        )
    except (RecursionError, TypeError, ValueError) as error:
        raise ValueError("invalid trusted Pwn leak records") from error
    if any(
        recipe.payload_source_run_id != identity.run_id
        for recipe, identity in zip(
            canonical_recipes,
            canonical_identities,
            strict=True,
        )
    ):
        raise ValueError("trusted Pwn leak run binding mismatch")
    result = PwnLeakTrustedReplayExpectation(
        preexisting_artifact_ids=tuple(
            sorted(preexisting_artifact_ids)
        ),
        replays=tuple(
            _trusted_replay_binding(recipe, identity)
            for recipe, identity in zip(
                canonical_recipes,
                canonical_identities,
                strict=True,
            )
        )
    )
    return PwnLeakTrustedReplayExpectation.from_dict(result.to_dict())


@dataclass(frozen=True, slots=True)
class PwnLeakReplayEvidence:
    """Exact bytes and typed runtime provenance for one clean replay."""

    ordinal: int
    payload: bytes = field(repr=False)
    recipe: PwnRuntimeSnapshotRecipe = field(repr=False)
    evaluation: PwnRuntimeSnapshotGateEvaluation = field(repr=False)
    receipt: PwnRuntimeSnapshotReceiptMetadata = field(repr=False)
    stdout_payload: bytes = field(repr=False)
    stderr_payload: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.ordinal) is not int
            or not 1 <= self.ordinal <= PWN_LEAK_REPLAY_COUNT
            or type(self.payload) is not bytes
            or not 1
            <= len(self.payload)
            <= PWN_RUNTIME_SNAPSHOT_V1_MAX_PAYLOAD_BYTES
            or type(self.recipe) is not PwnRuntimeSnapshotRecipe
            or type(self.evaluation)
            is not PwnRuntimeSnapshotGateEvaluation
            or type(self.receipt)
            is not PwnRuntimeSnapshotReceiptMetadata
            or type(self.stdout_payload) is not bytes
            or len(self.stdout_payload)
            > PWN_RUNTIME_SNAPSHOT_V1_MAX_DOCUMENT_BYTES
            or type(self.stderr_payload) is not bytes
            or len(self.stderr_payload) > PWN_DISCLOSURE_MAX_STREAM_BYTES
        ):
            raise ValueError("invalid Pwn leak replay evidence")


@dataclass(frozen=True, slots=True)
class PwnLeakReplayCommitment:
    ordinal: int
    nonce_sha256: str
    input_artifact_id: str
    input_sha256: str
    input_size_bytes: int
    recipe_sha256: str
    run_id: str
    receipt_id: str
    receipt_sha256: str
    request_sha256: str
    execution_contract_sha256: str
    capability_attestation_artifact_id: str
    capability_attestation_sha256: str
    stdout_artifact_id: str
    stdout_sha256: str
    stdout_size_bytes: int
    output_artifact_id: str
    output_sha256: str
    output_size_bytes: int
    evaluation_sha256: str
    observed_value_sha256: str
    map_base_sha256: str
    map_line_index: int
    map_line_sha256: str
    map_identity_sha256: str
    relative_offset_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.ordinal) is not int
            or not 1 <= self.ordinal <= PWN_LEAK_REPLAY_COUNT
            or any(
                not _sha256(getattr(self, field))
                for field in (
                    "nonce_sha256",
                    "input_sha256",
                    "recipe_sha256",
                    "receipt_sha256",
                    "request_sha256",
                    "execution_contract_sha256",
                    "capability_attestation_sha256",
                    "stdout_sha256",
                    "output_sha256",
                    "evaluation_sha256",
                    "observed_value_sha256",
                    "map_base_sha256",
                    "map_line_sha256",
                    "map_identity_sha256",
                    "relative_offset_sha256",
                )
            )
            or any(
                not _identifier(getattr(self, field))
                for field in (
                    "input_artifact_id",
                    "run_id",
                    "receipt_id",
                    "capability_attestation_artifact_id",
                    "stdout_artifact_id",
                    "output_artifact_id",
                )
            )
            or type(self.input_size_bytes) is not int
            or not 1
            <= self.input_size_bytes
            <= PWN_RUNTIME_SNAPSHOT_V1_MAX_PAYLOAD_BYTES
            or type(self.stdout_size_bytes) is not int
            or not 1
            <= self.stdout_size_bytes
            <= PWN_RUNTIME_SNAPSHOT_V1_MAX_DOCUMENT_BYTES
            or type(self.output_size_bytes) is not int
            or not 0
            <= self.output_size_bytes
            <= PWN_DISCLOSURE_MAX_STREAM_BYTES
            or type(self.map_line_index) is not int
            or not 1 <= self.map_line_index <= PWN_DISCLOSURE_MAX_MAP_LINES
        ):
            raise ValueError("invalid Pwn leak replay commitment")

    def to_dict(self) -> dict[str, object]:
        return {
            key: getattr(self, key) for key in sorted(_COMMITMENT_KEYS)
        }

    @classmethod
    def from_dict(
        cls,
        value: object,
    ) -> "PwnLeakReplayCommitment":
        if type(value) is not dict or set(value) != _COMMITMENT_KEYS:
            raise ValueError("invalid Pwn leak replay commitment schema")
        return cls(**value)


@dataclass(frozen=True, slots=True)
class PwnLeakResult:
    status: PwnLeakStatus
    reason_code: str
    plan_recipe_sha256: str
    trusted_replay_expectation_sha256: str
    disclosure_result_sha256: str
    source_manifest_sha256: str
    source_sha256: str
    source_size_bytes: int
    baseline_payload_sha256: str
    baseline_payload_size_bytes: int
    candidate_byte_offset: int
    candidate_hex_width: int
    replays: tuple[PwnLeakReplayCommitment, ...]
    distinct_runtime_value_count: int
    distinct_mapping_base_count: int
    stable_map_identity_sha256: str | None
    stable_relative_offset_sha256: str | None

    def __post_init__(self) -> None:
        if (
            type(self.status) is not PwnLeakStatus
            or type(self.reason_code) is not str
            or (
                self.status is PwnLeakStatus.PROVEN
                and self.reason_code != _PROVEN_REASON
            )
            or (
                self.status is PwnLeakStatus.UNVERIFIABLE
                and self.reason_code not in _UNVERIFIABLE_REASONS
            )
            or any(
                not _sha256(item)
                for item in (
                    self.plan_recipe_sha256,
                    self.trusted_replay_expectation_sha256,
                    self.disclosure_result_sha256,
                    self.source_manifest_sha256,
                    self.source_sha256,
                    self.baseline_payload_sha256,
                )
            )
            or type(self.source_size_bytes) is not int
            or not 1
            <= self.source_size_bytes
            <= PWN_RUNTIME_SNAPSHOT_V1_MAX_SOURCE_BYTES
            or type(self.baseline_payload_size_bytes) is not int
            or not 1
            <= self.baseline_payload_size_bytes
            <= PWN_RUNTIME_SNAPSHOT_V1_MAX_PAYLOAD_BYTES
            or type(self.candidate_byte_offset) is not int
            or self.candidate_byte_offset < 0
            or type(self.candidate_hex_width) is not int
            or not 6 <= self.candidate_hex_width <= 16
            or type(self.replays) is not tuple
            or len(self.replays) > PWN_LEAK_REPLAY_COUNT
            or any(
                type(item) is not PwnLeakReplayCommitment
                for item in self.replays
            )
            or tuple(item.ordinal for item in self.replays)
            != tuple(range(1, len(self.replays) + 1))
            or type(self.distinct_runtime_value_count) is not int
            or not 0
            <= self.distinct_runtime_value_count
            <= PWN_LEAK_REPLAY_COUNT
            or type(self.distinct_mapping_base_count) is not int
            or not 0
            <= self.distinct_mapping_base_count
            <= PWN_LEAK_REPLAY_COUNT
            or (
                self.stable_map_identity_sha256 is not None
                and not _sha256(self.stable_map_identity_sha256)
            )
            or (
                self.stable_relative_offset_sha256 is not None
                and not _sha256(self.stable_relative_offset_sha256)
            )
        ):
            raise ValueError("invalid Pwn leak result")
        if (
            self.distinct_runtime_value_count
            != len(
                {
                    item.observed_value_sha256
                    for item in self.replays
                }
            )
            or self.distinct_mapping_base_count
            != len(
                {
                    item.map_base_sha256
                    for item in self.replays
                }
            )
        ):
            raise ValueError("Pwn leak result summary mismatch")
        for field_name in (
            "input_artifact_id",
            "recipe_sha256",
            "run_id",
            "receipt_id",
            "receipt_sha256",
            "request_sha256",
            "execution_contract_sha256",
            "capability_attestation_artifact_id",
            "capability_attestation_sha256",
            "stdout_artifact_id",
            "output_artifact_id",
        ):
            values = tuple(
                getattr(item, field_name) for item in self.replays
            )
            if len(set(values)) != len(values):
                raise ValueError("Pwn leak result identity reused")
        artifact_ids = tuple(
            artifact_id
            for item in self.replays
            for artifact_id in (
                item.input_artifact_id,
                item.capability_attestation_artifact_id,
                item.stdout_artifact_id,
                item.output_artifact_id,
            )
        )
        if len(set(artifact_ids)) != len(artifact_ids):
            raise ValueError("Pwn leak result artifact identity collision")
        if (
            self.stable_map_identity_sha256 is not None
            and any(
                item.map_identity_sha256
                != self.stable_map_identity_sha256
                for item in self.replays
            )
        ):
            raise ValueError("Pwn leak result map summary mismatch")
        if (
            self.stable_relative_offset_sha256 is not None
            and any(
                item.relative_offset_sha256
                != self.stable_relative_offset_sha256
                for item in self.replays
            )
        ):
            raise ValueError("Pwn leak result offset summary mismatch")
        if self.status is PwnLeakStatus.PROVEN and (
            len(self.replays) != PWN_LEAK_REPLAY_COUNT
            or self.distinct_runtime_value_count < 2
            or self.distinct_mapping_base_count < 2
            or self.stable_map_identity_sha256 is None
            or self.stable_relative_offset_sha256 is None
            or len(
                {
                    item.map_identity_sha256
                    for item in self.replays
                }
            )
            != 1
            or len(
                {
                    item.relative_offset_sha256
                    for item in self.replays
                }
            )
            != 1
            or self.replays[0].input_sha256
            != self.replays[1].input_sha256
            or self.replays[2].input_sha256
            == self.replays[0].input_sha256
            or self.replays[0].nonce_sha256
            != self.replays[1].nonce_sha256
            or self.replays[2].nonce_sha256
            == self.replays[0].nonce_sha256
            or self.replays[0].map_base_sha256
            == self.replays[1].map_base_sha256
            or self.replays[0].observed_value_sha256
            == self.replays[1].observed_value_sha256
        ):
            raise ValueError("incomplete proven Pwn leak result")
        self.canonical_bytes()

    @property
    def leak_proven(self) -> bool:
        return self.status is PwnLeakStatus.PROVEN

    @property
    def evidence_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def to_dict(self) -> dict[str, object]:
        proven = self.leak_proven
        return {
            "authorities": {
                **_AUTHORITIES_FALSE,
                "leak_proven": proven,
            },
            "binding": {
                "baseline_payload_sha256": self.baseline_payload_sha256,
                "baseline_payload_size_bytes": (
                    self.baseline_payload_size_bytes
                ),
                "candidate_byte_offset": self.candidate_byte_offset,
                "candidate_hex_width": self.candidate_hex_width,
                "disclosure_result_sha256": (
                    self.disclosure_result_sha256
                ),
                "plan_recipe_sha256": self.plan_recipe_sha256,
                "source_manifest_sha256": (
                    self.source_manifest_sha256
                ),
                "source_sha256": self.source_sha256,
                "source_size_bytes": self.source_size_bytes,
                "trusted_replay_expectation_sha256": (
                    self.trusted_replay_expectation_sha256
                ),
            },
            "contract": {
                "fingerprint": PWN_LEAK_CONTRACT_FINGERPRINT,
                "id": PWN_LEAK_CONTRACT_ID,
                "version": PWN_LEAK_CONTRACT_VERSION,
            },
            "reason_code": self.reason_code,
            "replays": [item.to_dict() for item in self.replays],
            "schema_version": PWN_LEAK_SCHEMA_VERSION,
            "status": self.status.value,
            "summary": {
                "distinct_mapping_base_count": (
                    self.distinct_mapping_base_count
                ),
                "distinct_runtime_value_count": (
                    self.distinct_runtime_value_count
                ),
                "stable_map_identity_sha256": (
                    self.stable_map_identity_sha256
                ),
                "stable_relative_offset_sha256": (
                    self.stable_relative_offset_sha256
                ),
            },
        }

    def canonical_bytes(self) -> bytes:
        payload = _canonical_json_bytes(self.to_dict())
        if len(payload) > PWN_LEAK_MAX_RESULT_BYTES:
            raise ValueError("Pwn leak result exceeds byte limit")
        return payload

    @classmethod
    def from_dict(
        cls,
        value: object,
        *,
        expected_result: "PwnLeakResult | None" = None,
    ) -> "PwnLeakResult":
        if type(value) is not dict or set(value) != _RESULT_KEYS:
            raise ValueError("invalid Pwn leak result schema")
        authorities = value.get("authorities")
        binding = value.get("binding")
        contract = value.get("contract")
        summary = value.get("summary")
        replays = value.get("replays")
        if (
            type(authorities) is not dict
            or any(type(item) is not bool for item in authorities.values())
            or authorities
            != {
                **_AUTHORITIES_FALSE,
                "leak_proven": value.get("status") == "PROVEN",
            }
            or type(binding) is not dict
            or set(binding) != _RESULT_BINDING_KEYS
            or type(contract) is not dict
            or type(contract.get("version")) is not int
            or contract
            != {
                "fingerprint": PWN_LEAK_CONTRACT_FINGERPRINT,
                "id": PWN_LEAK_CONTRACT_ID,
                "version": PWN_LEAK_CONTRACT_VERSION,
            }
            or type(summary) is not dict
            or set(summary) != _SUMMARY_KEYS
            or type(replays) is not list
            or type(value.get("schema_version")) is not int
            or value.get("schema_version") != PWN_LEAK_SCHEMA_VERSION
            or type(value.get("status")) is not str
            or type(value.get("reason_code")) is not str
        ):
            raise ValueError("invalid Pwn leak result schema")
        try:
            result = cls(
                status=PwnLeakStatus(value["status"]),
                reason_code=value["reason_code"],
                plan_recipe_sha256=binding["plan_recipe_sha256"],
                trusted_replay_expectation_sha256=binding[
                    "trusted_replay_expectation_sha256"
                ],
                disclosure_result_sha256=binding[
                    "disclosure_result_sha256"
                ],
                source_manifest_sha256=binding[
                    "source_manifest_sha256"
                ],
                source_sha256=binding["source_sha256"],
                source_size_bytes=binding["source_size_bytes"],
                baseline_payload_sha256=binding[
                    "baseline_payload_sha256"
                ],
                baseline_payload_size_bytes=binding[
                    "baseline_payload_size_bytes"
                ],
                candidate_byte_offset=binding["candidate_byte_offset"],
                candidate_hex_width=binding["candidate_hex_width"],
                replays=tuple(
                    PwnLeakReplayCommitment.from_dict(item)
                    for item in replays
                ),
                distinct_runtime_value_count=summary[
                    "distinct_runtime_value_count"
                ],
                distinct_mapping_base_count=summary[
                    "distinct_mapping_base_count"
                ],
                stable_map_identity_sha256=summary[
                    "stable_map_identity_sha256"
                ],
                stable_relative_offset_sha256=summary[
                    "stable_relative_offset_sha256"
                ],
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("invalid Pwn leak result schema") from error
        if value != result.to_dict():
            raise ValueError("Pwn leak result is not reconstructable")
        if result.status is PwnLeakStatus.PROVEN and (
            type(expected_result) is not PwnLeakResult
            or result != expected_result
        ):
            raise ValueError(
                "proven Pwn leak result requires exact recomputation"
            )
        if (
            expected_result is not None
            and (
                type(expected_result) is not PwnLeakResult
                or result != expected_result
            )
        ):
            raise ValueError("Pwn leak result binding mismatch")
        return result


@dataclass(frozen=True, slots=True)
class _MapRange:
    start: int
    end: int
    line_index: int
    line_sha256: str
    identity_sha256: str

    def contains(self, value: int) -> bool:
        return self.start <= value < self.end


def _parse_maps(data: bytes) -> tuple[_MapRange, ...]:
    if (
        type(data) is not bytes
        or not 1 <= len(data) <= PWN_RUNTIME_SNAPSHOT_V1_MAX_MAPS_BYTES
        or not data.endswith(b"\n")
        or b"\x00" in data
    ):
        raise ValueError("maps_invalid")
    lines = data[:-1].split(b"\n")
    if (
        not lines
        or len(lines) > PWN_DISCLOSURE_MAX_MAP_LINES
        or any(
            not line or len(line) > PWN_DISCLOSURE_MAX_MAP_LINE_BYTES
            for line in lines
        )
    ):
        raise ValueError("maps_invalid")
    ranges: list[_MapRange] = []
    previous_end = 0
    for line_index, line in enumerate(lines, start=1):
        match = _MAP_LINE.fullmatch(line)
        if match is None:
            raise ValueError("maps_invalid")
        try:
            start = int(match.group("start"), 16)
            end = int(match.group("end"), 16)
            offset = int(match.group("offset"), 16)
            major = int(match.group("major"), 16)
            minor = int(match.group("minor"), 16)
            inode = int(match.group("inode"), 10)
        except ValueError as error:
            raise ValueError("maps_invalid") from error
        if (
            not 0 <= start < end <= _U64_MAX + 1
            or start < previous_end
            or any(
                not 0 <= item <= _U64_MAX
                for item in (offset, major, minor, inode)
            )
        ):
            raise ValueError("maps_invalid")
        pathname = match.group("pathname") or b""
        identity = {
            "file_offset": offset,
            "line_index": line_index,
            "pathname_sha256": hashlib.sha256(pathname).hexdigest(),
            "permissions": match.group("permissions").decode("ascii"),
        }
        ranges.append(
            _MapRange(
                start=start,
                end=end,
                line_index=line_index,
                line_sha256=hashlib.sha256(line + b"\n").hexdigest(),
                identity_sha256=hashlib.sha256(
                    _canonical_json_bytes(identity)
                ).hexdigest(),
            )
        )
        previous_end = end
    return tuple(ranges)


def _payload_contains_value(payload: bytes, raw: bytes, value: int) -> bool:
    lowered = payload.lower()
    minimal = f"0x{value:x}".encode("ascii")
    raw_digits = raw[2:].lower()
    minimal_digits = f"{value:x}".encode("ascii")
    decimal = str(value).encode("ascii")
    if (
        raw.lower() in lowered
        or raw_digits in lowered
        or minimal in lowered
        or minimal_digits in lowered
        or decimal in payload
    ):
        return True
    minimum_width = max(1, (value.bit_length() + 7) // 8)
    for width in range(minimum_width, 9):
        if (
            value.to_bytes(width, "little") in payload
            or value.to_bytes(width, "big") in payload
        ):
            return True
    return False


def _receipt_sha256(receipt: PwnRuntimeSnapshotReceiptMetadata) -> str:
    return hashlib.sha256(
        _canonical_json_bytes(receipt.to_dict())
    ).hexdigest()


def _same_runtime_binding(
    baseline: PwnRuntimeSnapshotRecipe,
    replay: PwnRuntimeSnapshotRecipe,
) -> bool:
    return all(
        getattr(baseline, field) == getattr(replay, field)
        for field in (
            "configuration_epoch",
            "child_experiment_id",
            "parent_experiment_id",
            "primary_elf_locator",
            "source_manifest_sha256",
            "source_sha256",
            "source_size_bytes",
            "parent_crash_recipe_sha256",
            "parent_crash_evaluation_sha256",
            "expected_signal_number",
            "image_reference",
            "image_digest",
            "producer_file_sha256",
        )
    )


def _receipt_valid(
    evidence: PwnLeakReplayEvidence,
) -> bool:
    recipe = evidence.recipe
    evaluation = evidence.evaluation
    receipt = evidence.receipt
    semantic = evaluation.semantic_result
    if semantic is None or semantic.maps is None:
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
        and receipt.run_id == recipe.payload_source_run_id
        and receipt.producer_capability_name
        == PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME
        and receipt.producer_file_sha256
        == recipe.producer_file_sha256
        == PWN_RUNTIME_SNAPSHOT_PRODUCER_FILE_SHA256
        and receipt.capability_attestation_sha256
        == expected_attestation
        and receipt.stderr_capture_placeholder is False
        and receipt.stderr_artifact_sha256
        == hashlib.sha256(evidence.stderr_payload).hexdigest()
        and receipt.stderr_artifact_size_bytes
        == len(evidence.stderr_payload)
        and receipt.stdout_capture_complete is True
        and receipt.stdout_truncation_known is True
        and receipt.stdout_truncated is False
        and receipt.stdout_error is None
        and receipt.stream_capture_error is None
        and receipt.orchestration_error is None
        and receipt.durable_stdout_artifact_complete is True
        and receipt.stdout_artifact_id is not None
        and receipt.stdout_artifact_sha256
        == hashlib.sha256(semantic_bytes).hexdigest()
        == hashlib.sha256(evidence.stdout_payload).hexdigest()
        and receipt.stdout_artifact_size_bytes
        == len(semantic_bytes)
        == len(evidence.stdout_payload)
        and receipt.stdout_drained_bytes == len(semantic_bytes)
        and receipt.stdout_stored_bytes == len(semantic_bytes)
    )


def _result(
    plan: PwnLeakPlan,
    trusted_replay_expectation: PwnLeakTrustedReplayExpectation,
    reason_code: str,
    commitments: tuple[PwnLeakReplayCommitment, ...],
    *,
    values: tuple[int, ...] = (),
    bases: tuple[int, ...] = (),
    map_identity_sha256: str | None = None,
    relative_offset_sha256: str | None = None,
) -> PwnLeakResult:
    proven = reason_code == _PROVEN_REASON
    return PwnLeakResult(
        status=(
            PwnLeakStatus.PROVEN
            if proven
            else PwnLeakStatus.UNVERIFIABLE
        ),
        reason_code=reason_code,
        plan_recipe_sha256=plan.recipe_sha256,
        trusted_replay_expectation_sha256=(
            trusted_replay_expectation.evidence_sha256
        ),
        disclosure_result_sha256=plan.disclosure_result_sha256,
        source_manifest_sha256=plan.source_manifest_sha256,
        source_sha256=plan.source_sha256,
        source_size_bytes=plan.source_size_bytes,
        baseline_payload_sha256=plan.baseline_payload_sha256,
        baseline_payload_size_bytes=plan.baseline_payload_size_bytes,
        candidate_byte_offset=plan.candidate_byte_offset,
        candidate_hex_width=plan.candidate_hex_width,
        replays=commitments,
        distinct_runtime_value_count=len(set(values)),
        distinct_mapping_base_count=len(set(bases)),
        stable_map_identity_sha256=map_identity_sha256,
        stable_relative_offset_sha256=relative_offset_sha256,
    )


def evaluate_pwn_leak(
    *,
    disclosure: PwnDisclosureResult,
    baseline_snapshot_recipe: PwnRuntimeSnapshotRecipe,
    baseline_payload: bytes,
    plan: PwnLeakPlan,
    trusted_replay_expectation: PwnLeakTrustedReplayExpectation,
    replays: tuple[PwnLeakReplayEvidence, ...],
) -> PwnLeakResult:
    """Prove or reject one output-locus runtime address disclosure."""

    if (
        type(disclosure) is not PwnDisclosureResult
        or type(baseline_snapshot_recipe)
        is not PwnRuntimeSnapshotRecipe
        or type(baseline_payload) is not bytes
        or type(plan) is not PwnLeakPlan
        or type(trusted_replay_expectation)
        is not PwnLeakTrustedReplayExpectation
    ):
        raise TypeError("exact Pwn leak inputs are required")
    _require_current_contract_fingerprint()
    try:
        if (
            PwnLeakTrustedReplayExpectation.from_dict(
                trusted_replay_expectation.to_dict()
            )
            != trusted_replay_expectation
        ):
            raise ValueError("trusted replay expectation changed")
    except (RecursionError, TypeError, ValueError) as error:
        raise ValueError("invalid trusted Pwn leak expectation") from error
    try:
        rebuilt = derive_pwn_leak_plan(
            disclosure,
            baseline_snapshot_recipe,
            baseline_payload,
            candidate_byte_offset=plan.candidate_byte_offset,
            candidate_hex_width=plan.candidate_hex_width,
            nonce_offset=plan.nonce_offset,
            nonce_width_bytes=plan.nonce_width_bytes,
        )
    except (TypeError, ValueError):
        return _result(
            plan,
            trusted_replay_expectation,
            "disclosure_not_eligible",
            (),
        )
    if rebuilt != plan:
        return _result(
            plan,
            trusted_replay_expectation,
            "plan_binding_mismatch",
            (),
        )
    if (
        type(replays) is not tuple
        or len(replays) != PWN_LEAK_REPLAY_COUNT
        or any(type(item) is not PwnLeakReplayEvidence for item in replays)
        or tuple(item.ordinal for item in replays)
        != tuple(range(1, PWN_LEAK_REPLAY_COUNT + 1))
    ):
        return _result(
            plan,
            trusted_replay_expectation,
            "replay_recipe_binding_mismatch",
            (),
        )

    baseline_receipt = (
        disclosure.binding.upstream.runtime_snapshot_receipt
    )
    identities: dict[str, set[str]] = {
        "payload_artifact_id": {
            baseline_snapshot_recipe.payload_artifact_id
        },
        "payload_source_run_id": {
            baseline_snapshot_recipe.payload_source_run_id
        },
        "payload_artifact_locator": {
            baseline_snapshot_recipe.payload_artifact_locator
        },
        "recipe_sha256": {
            baseline_snapshot_recipe.recipe_sha256
        },
        "receipt_id": {baseline_receipt.receipt_id},
        "run_id": {baseline_receipt.run_id},
        "request_sha256": {baseline_receipt.request_sha256},
        "execution_contract_sha256": {
            baseline_receipt.execution_contract_sha256
        },
        "capability_attestation_artifact_id": set(),
        "stdout_artifact_id": {baseline_receipt.stdout.artifact_id},
        "stderr_artifact_id": {baseline_receipt.stderr.artifact_id},
    }
    upstream_receipts = (
        *disclosure.binding.upstream.positive_receipts,
        baseline_receipt,
    )
    seen_artifact_ids = {
        baseline_snapshot_recipe.payload_artifact_id,
        *(
            artifact.artifact_id
            for upstream_receipt in upstream_receipts
            for artifact in (
                upstream_receipt.stdout,
                upstream_receipt.stderr,
            )
        ),
    }
    commitments: list[PwnLeakReplayCommitment] = []
    values: list[int] = []
    bases: list[int] = []
    identities_sha: list[str] = []
    relative_offsets: list[int] = []
    plan_records = plan.to_dict()["replays"]
    assert isinstance(plan_records, list)

    for (
        evidence,
        expected_payload,
        expected_nonce,
        plan_record,
        trusted_binding,
    ) in zip(
        replays,
        plan.payloads,
        plan.nonces,
        plan_records,
        trusted_replay_expectation.replays,
        strict=True,
    ):
        recipe = evidence.recipe
        receipt = evidence.receipt
        try:
            if (
                PwnRuntimeSnapshotRecipe.from_dict(recipe.to_dict())
                != recipe
                or PwnRuntimeSnapshotReceiptMetadata.from_dict(
                    receipt.to_dict()
                )
                != receipt
                or PwnRuntimeSnapshotGateEvaluation.from_dict(
                    evidence.evaluation.to_dict(),
                    recipe=recipe,
                )
                != evidence.evaluation
            ):
                raise ValueError("typed replay provenance changed")
        except (RecursionError, TypeError, ValueError):
            return _result(
                plan,
                trusted_replay_expectation,
                "replay_receipt_binding_mismatch",
                tuple(commitments),
                values=tuple(values),
                bases=tuple(bases),
            )
        if (
            evidence.payload != expected_payload
            or evidence.payload[: plan.nonce_offset]
            != baseline_payload[: plan.nonce_offset]
            or evidence.payload[
                plan.nonce_offset + plan.nonce_width_bytes :
            ]
            != baseline_payload[
                plan.nonce_offset + plan.nonce_width_bytes :
            ]
            or evidence.payload[
                plan.nonce_offset :
                plan.nonce_offset + plan.nonce_width_bytes
            ]
            != expected_nonce
            or hashlib.sha256(evidence.payload).hexdigest()
            != plan_record["input_sha256"]
        ):
            return _result(
                plan,
                trusted_replay_expectation,
                "input_variant_mismatch",
                tuple(commitments),
                values=tuple(values),
                bases=tuple(bases),
            )
        if (
            not _same_runtime_binding(
                baseline_snapshot_recipe,
                recipe,
            )
            or recipe.payload_sha256
            != hashlib.sha256(evidence.payload).hexdigest()
            or recipe.payload_size_bytes != len(evidence.payload)
            or recipe.payload_source_run_id != receipt.run_id
        ):
            return _result(
                plan,
                trusted_replay_expectation,
                "replay_recipe_binding_mismatch",
                tuple(commitments),
                values=tuple(values),
                bases=tuple(bases),
            )
        try:
            observed_identity = PwnLeakPreissuedReplayIdentity(
                ordinal=evidence.ordinal,
                run_id=receipt.run_id,
                receipt_id=receipt.receipt_id,
                request_sha256=receipt.request_sha256,
                execution_contract_sha256=(
                    receipt.execution_contract_sha256
                ),
                capability_attestation_artifact_id=(
                    receipt.capability_attestation_artifact_id
                ),
                stdout_artifact_id=receipt.stdout_artifact_id or "",
                output_artifact_id=receipt.stderr_artifact_id,
            )
        except ValueError:
            return _result(
                plan,
                trusted_replay_expectation,
                "trusted_replay_expectation_mismatch",
                tuple(commitments),
                values=tuple(values),
                bases=tuple(bases),
            )
        if (
            _trusted_replay_binding(recipe, observed_identity)
            != trusted_binding
        ):
            return _result(
                plan,
                trusted_replay_expectation,
                "trusted_replay_expectation_mismatch",
                tuple(commitments),
                values=tuple(values),
                bases=tuple(bases),
            )
        current_identities = {
            "payload_artifact_id": recipe.payload_artifact_id,
            "payload_source_run_id": recipe.payload_source_run_id,
            "payload_artifact_locator": (
                recipe.payload_artifact_locator
            ),
            "recipe_sha256": recipe.recipe_sha256,
            "receipt_id": receipt.receipt_id,
            "run_id": receipt.run_id,
            "request_sha256": receipt.request_sha256,
            "execution_contract_sha256": (
                receipt.execution_contract_sha256
            ),
            "capability_attestation_artifact_id": (
                receipt.capability_attestation_artifact_id
            ),
            "stdout_artifact_id": receipt.stdout_artifact_id or "",
            "stderr_artifact_id": receipt.stderr_artifact_id,
        }
        current_artifact_ids = {
            recipe.payload_artifact_id,
            receipt.capability_attestation_artifact_id,
            receipt.stdout_artifact_id or "",
            receipt.stderr_artifact_id,
        }
        if any(
            value in identities[name]
            for name, value in current_identities.items()
        ) or bool(current_artifact_ids & seen_artifact_ids):
            return _result(
                plan,
                trusted_replay_expectation,
                "replay_identity_reused",
                tuple(commitments),
                values=tuple(values),
                bases=tuple(bases),
            )
        for name, value in current_identities.items():
            identities[name].add(value)
        seen_artifact_ids.update(current_artifact_ids)

        recomputed = evaluate_pwn_runtime_snapshot_gate(
            recipe,
            stdout_payload=evidence.stdout_payload,
            receipt=receipt,
        )
        if recomputed != evidence.evaluation:
            return _result(
                plan,
                trusted_replay_expectation,
                "replay_gate_changed",
                tuple(commitments),
                values=tuple(values),
                bases=tuple(bases),
            )
        if not _receipt_valid(evidence):
            return _result(
                plan,
                trusted_replay_expectation,
                "replay_receipt_binding_mismatch",
                tuple(commitments),
                values=tuple(values),
                bases=tuple(bases),
            )
        semantic = recomputed.semantic_result
        if (
            not recomputed.captured
            or semantic is None
            or semantic.maps is None
        ):
            return _result(
                plan,
                trusted_replay_expectation,
                "replay_not_captured",
                tuple(commitments),
                values=tuple(values),
                bases=tuple(bases),
            )

        selected = None
        for match in _POINTER_TOKEN.finditer(evidence.stderr_payload):
            if (
                match.start() == plan.candidate_byte_offset
                and len(match.group(1)) == plan.candidate_hex_width
            ):
                selected = match
                break
        if selected is None:
            return _result(
                plan,
                trusted_replay_expectation,
                "stable_locus_missing",
                tuple(commitments),
                values=tuple(values),
                bases=tuple(bases),
            )
        raw_token = selected.group(0)
        value = int(selected.group(1), 16)
        if _payload_contains_value(evidence.payload, raw_token, value):
            return _result(
                plan,
                trusted_replay_expectation,
                "pointer_payload_derived",
                tuple(commitments),
                values=tuple(values),
                bases=tuple(bases),
            )
        try:
            ranges = _parse_maps(semantic.maps.data)
        except ValueError:
            return _result(
                plan,
                trusted_replay_expectation,
                "maps_invalid",
                tuple(commitments),
                values=tuple(values),
                bases=tuple(bases),
            )
        mapped = next(
            (item for item in ranges if item.contains(value)),
            None,
        )
        if mapped is None:
            return _result(
                plan,
                trusted_replay_expectation,
                "pointer_unmapped",
                tuple(commitments),
                values=tuple(values),
                bases=tuple(bases),
            )
        relative_offset = value - mapped.start
        observed_sha = _hash_u64(value)
        base_sha = _hash_u64(mapped.start)
        relative_sha = _hash_u64(relative_offset)
        commitment = PwnLeakReplayCommitment(
            ordinal=evidence.ordinal,
            nonce_sha256=hashlib.sha256(expected_nonce).hexdigest(),
            input_artifact_id=recipe.payload_artifact_id,
            input_sha256=recipe.payload_sha256,
            input_size_bytes=recipe.payload_size_bytes,
            recipe_sha256=recipe.recipe_sha256,
            run_id=receipt.run_id,
            receipt_id=receipt.receipt_id,
            receipt_sha256=_receipt_sha256(receipt),
            request_sha256=receipt.request_sha256,
            execution_contract_sha256=(
                receipt.execution_contract_sha256
            ),
            capability_attestation_artifact_id=(
                receipt.capability_attestation_artifact_id
            ),
            capability_attestation_sha256=(
                receipt.capability_attestation_sha256
            ),
            stdout_artifact_id=receipt.stdout_artifact_id or "",
            stdout_sha256=receipt.stdout_artifact_sha256 or "",
            stdout_size_bytes=receipt.stdout_artifact_size_bytes or 0,
            output_artifact_id=receipt.stderr_artifact_id,
            output_sha256=receipt.stderr_artifact_sha256,
            output_size_bytes=receipt.stderr_artifact_size_bytes,
            evaluation_sha256=recomputed.evidence_sha256,
            observed_value_sha256=observed_sha,
            map_base_sha256=base_sha,
            map_line_index=mapped.line_index,
            map_line_sha256=mapped.line_sha256,
            map_identity_sha256=mapped.identity_sha256,
            relative_offset_sha256=relative_sha,
        )
        commitments.append(commitment)
        values.append(value)
        bases.append(mapped.start)
        identities_sha.append(mapped.identity_sha256)
        relative_offsets.append(relative_offset)

    if len(set(identities_sha)) != 1:
        return _result(
            plan,
            trusted_replay_expectation,
            "mapping_identity_changed",
            tuple(commitments),
            values=tuple(values),
            bases=tuple(bases),
        )
    if len(set(relative_offsets)) != 1:
        return _result(
            plan,
            trusted_replay_expectation,
            "relative_offset_changed",
            tuple(commitments),
            values=tuple(values),
            bases=tuple(bases),
            map_identity_sha256=identities_sha[0],
        )
    if bases[0] == bases[1] or values[0] == values[1]:
        return _result(
            plan,
            trusted_replay_expectation,
            "paired_control_runtime_state_not_varied",
            tuple(commitments),
            values=tuple(values),
            bases=tuple(bases),
            map_identity_sha256=identities_sha[0],
            relative_offset_sha256=_hash_u64(relative_offsets[0]),
        )
    if len(set(bases)) < 2:
        return _result(
            plan,
            trusted_replay_expectation,
            "runtime_base_not_varied",
            tuple(commitments),
            values=tuple(values),
            bases=tuple(bases),
            map_identity_sha256=identities_sha[0],
            relative_offset_sha256=_hash_u64(relative_offsets[0]),
        )
    if len(set(values)) < 2:
        return _result(
            plan,
            trusted_replay_expectation,
            "leaked_value_not_varied",
            tuple(commitments),
            values=tuple(values),
            bases=tuple(bases),
            map_identity_sha256=identities_sha[0],
            relative_offset_sha256=_hash_u64(relative_offsets[0]),
        )
    return _result(
        plan,
        trusted_replay_expectation,
        _PROVEN_REASON,
        tuple(commitments),
        values=tuple(values),
        bases=tuple(bases),
        map_identity_sha256=identities_sha[0],
        relative_offset_sha256=_hash_u64(relative_offsets[0]),
    )


def evaluate_pwn_leak_strategy_advisory(
    strategy: PwnLeakRequirementV1Strategy,
    *,
    dependency_id: object,
    elf_profile: PwnLeakRequirementV1ElfProfile,
) -> PwnLeakRequirementV1Result:
    """Return an existing v1 advisory scoped to one strategy dependency.

    In particular, ``CONDITIONAL_NOT_APPLICABLE`` is never interpreted as a
    global leak N/A decision.  The returned contract keeps every global,
    proof, primitive, and stage authority false.
    """

    if (
        type(strategy) is not PwnLeakRequirementV1Strategy
        or type(elf_profile) is not PwnLeakRequirementV1ElfProfile
    ):
        raise TypeError("exact leak-requirement strategy/profile required")
    result = classify_pwn_leak_requirement_v1(
        strategy,
        dependency_id=dependency_id,
        elf_profile=elf_profile,
    )
    claims = result.to_dict()["claims"]
    if not isinstance(claims, dict) or any(claims.values()):
        raise ValueError("Pwn leak advisory acquired authority")
    return result


def validate_pwn_leak_result(
    value: object,
    *,
    expected_result: PwnLeakResult,
) -> PwnLeakResult:
    """Validate a mapping only against an independently recomputed result."""

    if type(expected_result) is not PwnLeakResult:
        raise TypeError("expected_result must be exact PwnLeakResult")
    return PwnLeakResult.from_dict(
        value,
        expected_result=expected_result,
    )


__all__ = [
    "PWN_LEAK_CONTRACT_FINGERPRINT",
    "PWN_LEAK_CONTRACT_ID",
    "PWN_LEAK_CONTRACT_VERSION",
    "PWN_LEAK_MAX_NONCE_BYTES",
    "PWN_LEAK_MIN_NONCE_BYTES",
    "PWN_LEAK_REPLAY_COUNT",
    "PWN_LEAK_SCHEMA_VERSION",
    "PwnLeakPlan",
    "PwnLeakPreissuedReplayIdentity",
    "PwnLeakReplayCommitment",
    "PwnLeakReplayEvidence",
    "PwnLeakResult",
    "PwnLeakStatus",
    "PwnLeakTrustedReplayBinding",
    "PwnLeakTrustedReplayExpectation",
    "build_pwn_leak_trusted_replay_expectation",
    "derive_pwn_leak_plan",
    "evaluate_pwn_leak",
    "evaluate_pwn_leak_strategy_advisory",
    "pwn_leak_child_experiment_id",
    "pwn_leak_contract_descriptor",
    "validate_pwn_leak_plan_document",
    "validate_pwn_leak_result",
]
