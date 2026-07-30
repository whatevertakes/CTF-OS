"""Fail-closed x86_64 instruction-pointer control partial oracle.

The oracle starts from one already-captured, engine-owned Pwn runtime
snapshot.  It is applicable only when the exact eight little-endian bytes of
the observed RIP occur at one and only one offset in the original payload.
It then derives three distinct canonical user-space addresses from the exact
upstream evidence, changes only those eight bytes, and requires three clean
runtime-snapshot gate evaluations in which RIP follows the derived address.

This module does not execute anything and does not mutate challenge state.
The caller must execute the returned payload variants through the existing
``PwnRuntimeSnapshotRecipe`` clean-sandbox path and pass the exact stdout and
receipt back to :func:`evaluate_pwn_ip_control`.  That function recomputes
every runtime-snapshot gate before granting authority.

The durable result contains artifact identities, byte offsets, and SHA-256
commitments only.  It never contains payload bytes, register values, maps
text, or target addresses.  A positive result proves only the narrow
instruction-pointer-control primitive; it cannot prove an exploit, proof,
flag, or authorize a stage transition.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum

from ctf_os.contracts.pwn_crash_v1 import PwnCrashV1Verdict
from ctf_os.contracts.pwn_runtime_snapshot_v1 import (
    PWN_RUNTIME_SNAPSHOT_V1_MAX_DOCUMENT_BYTES,
    PWN_RUNTIME_SNAPSHOT_V1_MAX_PAYLOAD_BYTES,
    PWN_RUNTIME_SNAPSHOT_V1_MAX_SOURCE_BYTES,
    PwnRuntimeSnapshotV1Status,
)
from ctf_os.engine.pwn_crash import (
    PwnCrashGateEvaluation,
    PwnCrashRecipe,
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


PWN_IP_CONTROL_SCHEMA_VERSION = 1
PWN_IP_CONTROL_CONTRACT_ID = "ctfos.pwn.ip_control"
PWN_IP_CONTROL_CONTRACT_VERSION = 1
PWN_IP_CONTROL_REPLAY_COUNT = 3
PWN_IP_CONTROL_WIDTH_BYTES = 8
PWN_IP_CONTROL_EXPECTED_SIGNAL = 11
PWN_IP_CONTROL_MAX_RESULT_BYTES = 64 * 1024
PWN_IP_CONTROL_TARGET_PREFIX = 0x0000600000000000
PWN_IP_CONTROL_TARGET_MASK = (1 << 40) - 1
PWN_IP_CONTROL_MAX_DERIVATION_ATTEMPTS = 256
PWN_IP_CONTROL_MAX_IDENTIFIER_BYTES = 512

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,511}$")
_MAP_LINE = re.compile(
    rb"(?P<start>[0-9a-f]{1,16})-(?P<end>[0-9a-f]{1,16})[ ]+"
    rb"(?P<permissions>[r-][w-][x-][ps])[ ]+"
    rb"(?P<offset>[0-9a-f]{1,16})[ ]+"
    rb"(?P<major>[0-9a-f]{1,8}):(?P<minor>[0-9a-f]{1,8})[ ]+"
    rb"(?P<inode>[0-9]{1,20})"
    rb"(?:[ ]+(?P<pathname>[\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?))?"
    rb"[ ]*"
)

_AUTHORITIES_FALSE = {
    "exploit_proven": False,
    "flag_proven": False,
    "proof_satisfied": False,
    "stage_advance_authorized": False,
}
_UNVERIFIABLE_REASONS = frozenset(
    {
        "baseline_gate_changed",
        "baseline_maps_invalid",
        "baseline_not_captured",
        "baseline_payload_binding_mismatch",
        "baseline_receipt_binding_mismatch",
        "baseline_signal_not_sigsegv",
        "cross_replay_binding_mismatch",
        "instruction_pointer_mismatch",
        "parent_crash_binding_mismatch",
        "parent_crash_not_confirmed",
        "replay_gate_changed",
        "replay_identity_reused",
        "replay_maps_invalid",
        "replay_not_captured",
        "replay_payload_binding_mismatch",
        "replay_payload_not_exact_variant",
        "replay_receipt_binding_mismatch",
        "rip_not_payload_derived",
        "rip_offset_ambiguous",
        "target_address_mapped",
        "target_bytes_not_unique",
        "target_derivation_exhausted",
    }
)
_PROVEN_REASON = "instruction_pointer_control_reproduced"
_RESULT_KEYS = frozenset(
    {
        "authorities",
        "baseline",
        "binding",
        "contract",
        "reason_code",
        "replays",
        "schema_version",
        "status",
    }
)
_CONTRACT_KEYS = frozenset({"fingerprint", "id", "version"})
_BINDING_KEYS = frozenset(
    {
        "controlled_offset",
        "controlled_width_bytes",
        "derivation_seed_sha256",
        "plan_recipe_sha256",
        "parent_crash_evaluation_sha256",
        "parent_crash_recipe_sha256",
        "source_manifest_sha256",
        "source_sha256",
        "source_size_bytes",
    }
)
_EVIDENCE_KEYS = frozenset(
    {
        "capability_attestation_artifact_id",
        "capability_attestation_sha256",
        "evaluation_sha256",
        "payload_artifact_id",
        "payload_sha256",
        "payload_size_bytes",
        "receipt_sha256",
        "recipe_sha256",
        "stdout_artifact_id",
        "stdout_artifact_sha256",
        "stdout_artifact_size_bytes",
    }
)
_REPLAY_KEYS = frozenset(
    set(_EVIDENCE_KEYS) | {"ordinal", "target_value_sha256"}
)
_AUTHORITY_KEYS = frozenset(
    {
        "exploit_proven",
        "flag_proven",
        "instruction_pointer_control_proven",
        "primitive_proven",
        "proof_satisfied",
        "stage_advance_authorized",
    }
)
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
        "baseline_evaluation_sha256",
        "baseline_recipe_sha256",
        "controlled_offset",
        "controlled_width_bytes",
        "derivation_seed_sha256",
        "original_payload_sha256",
        "original_payload_size_bytes",
        "parent_crash_evaluation_sha256",
        "parent_crash_recipe_sha256",
    }
)
_PLAN_REPLAY_KEYS = frozenset(
    {
        "ordinal",
        "payload_sha256",
        "payload_size_bytes",
        "target_value_sha256",
    }
)
_PLAN_DERIVATION_ALGORITHM = (
    "sha256-domain-seed-ordinal-attempt;"
    "prefix-0x000060-plus-40-bits;first-distinct-"
    "unmapped-baseline-and-not-in-original"
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


def pwn_ip_control_contract_descriptor() -> dict[str, object]:
    """Return the immutable semantic descriptor for the v1 partial oracle."""

    return {
        "authority": {
            **_AUTHORITIES_FALSE,
            "instruction_pointer_control_proven": (
                "true-only-after-three-exact-clean-replays"
            ),
            "primitive_proven": (
                "equals-instruction_pointer_control_proven"
            ),
        },
        "baseline": {
            "architecture": "x86_64",
            "offset_rule": (
                "exact-eight-byte-little-endian-rip-occurs-once-in-"
                "exact-original-payload"
            ),
            "required_signal": PWN_IP_CONTROL_EXPECTED_SIGNAL,
            "runtime_gate": "exact-recomputed-pwn-runtime-snapshot-v1",
        },
        "contract_id": PWN_IP_CONTROL_CONTRACT_ID,
        "contract_version": PWN_IP_CONTROL_CONTRACT_VERSION,
        "derivation": {
            "attempts_per_replay": (
                PWN_IP_CONTROL_MAX_DERIVATION_ATTEMPTS
            ),
            "domain": "ctfos.pwn.ip_control.target.v1",
            "input": (
                "source-and-parent-bindings-original-payload-hash-"
                "baseline-recipe-and-evaluation-hashes"
            ),
            "target_family": (
                "canonical-lower-user-address-prefix-0x000060-"
                "plus-40-derived-bits"
            ),
            "target_mask": f"{PWN_IP_CONTROL_TARGET_MASK:016x}",
            "target_prefix": f"{PWN_IP_CONTROL_TARGET_PREFIX:016x}",
        },
        "metamorphic_replays": {
            "count": PWN_IP_CONTROL_REPLAY_COUNT,
            "mutation": (
                "only-eight-bytes-at-engine-derived-controlled-offset"
            ),
            "requirements": [
                "exact-payload-recipe-and-semantic-binding",
                "clean-one-shot-network-none-receipt",
                "pinned-producer-observed-expected-sigsegv-stop",
                "pinned-producer-complete-proc-maps-or-error",
                "distinct-run-receipt-request-execution-and-artifact-ids",
                "captured-sigsegv",
                "rip-equals-derived-target",
                "target-unmapped-in-strict-proc-maps",
                "target-bytes-occur-once-in-variant",
            ],
        },
        "persistence": {
            "maximum_result_bytes": PWN_IP_CONTROL_MAX_RESULT_BYTES,
            "plan_recipe": (
                "canonical-raw-free-seed-offset-algorithm-and-three-"
                "target-plus-variant-sha256-commitments"
            ),
            "raw_maps": False,
            "raw_payload": False,
            "raw_registers": False,
            "raw_target_addresses": False,
            "target_commitment": "sha256(unsigned-64-little-endian)",
        },
        "schema_version": PWN_IP_CONTROL_SCHEMA_VERSION,
    }


PWN_IP_CONTROL_CONTRACT_FINGERPRINT = hashlib.sha256(
    _canonical_json_bytes(pwn_ip_control_contract_descriptor())
).hexdigest()


def pwn_ip_control_child_experiment_id(
    baseline_experiment_id: str,
) -> str:
    """Return the only primitive child id for one runtime snapshot."""

    if (
        type(baseline_experiment_id) is not str
        or len(baseline_experiment_id.encode("utf-8"))
        > PWN_IP_CONTROL_MAX_IDENTIFIER_BYTES
        or _IDENTIFIER.fullmatch(baseline_experiment_id) is None
    ):
        raise ValueError("invalid Pwn IP-control baseline experiment id")
    digest = hashlib.sha256(
        baseline_experiment_id.encode("utf-8")
    ).hexdigest()
    return f"E-pwn-ip-control-v1-{digest}"


class PwnIpControlStatus(str, Enum):
    PROVEN = "PROVEN"
    UNVERIFIABLE = "UNVERIFIABLE"


@dataclass(frozen=True, slots=True)
class PwnIpControlReplayEvidence:
    """Exact bytes and runtime provenance for one sandbox replay."""

    ordinal: int
    payload: bytes
    recipe: PwnRuntimeSnapshotRecipe
    evaluation: PwnRuntimeSnapshotGateEvaluation
    receipt: PwnRuntimeSnapshotReceiptMetadata
    stdout_payload: bytes

    def __post_init__(self) -> None:
        if type(self.ordinal) is not int or not 0 <= self.ordinal <= 3:
            raise ValueError("invalid Pwn IP-control replay ordinal")
        if (
            type(self.payload) is not bytes
            or not 1
            <= len(self.payload)
            <= PWN_RUNTIME_SNAPSHOT_V1_MAX_PAYLOAD_BYTES
            or type(self.recipe) is not PwnRuntimeSnapshotRecipe
            or type(self.evaluation)
            is not PwnRuntimeSnapshotGateEvaluation
            or type(self.receipt)
            is not PwnRuntimeSnapshotReceiptMetadata
            or type(self.stdout_payload) is not bytes
        ):
            raise ValueError("invalid Pwn IP-control replay evidence")


@dataclass(frozen=True, slots=True)
class PwnIpControlPlan:
    """Non-authoritative deterministic payload variants for clean replay."""

    controlled_offset: int
    derivation_seed_sha256: str
    baseline_recipe_sha256: str
    baseline_evaluation_sha256: str
    original_payload_sha256: str
    original_payload_size_bytes: int
    parent_crash_recipe_sha256: str
    parent_crash_evaluation_sha256: str
    targets: tuple[int, ...]
    payloads: tuple[bytes, ...]

    def __post_init__(self) -> None:
        if (
            type(self.controlled_offset) is not int
            or self.controlled_offset < 0
            or type(self.derivation_seed_sha256) is not str
            or _SHA256.fullmatch(self.derivation_seed_sha256) is None
            or type(self.targets) is not tuple
            or len(self.targets) != PWN_IP_CONTROL_REPLAY_COUNT
            or len(set(self.targets)) != len(self.targets)
            or type(self.payloads) is not tuple
            or len(self.payloads) != PWN_IP_CONTROL_REPLAY_COUNT
        ):
            raise ValueError("invalid Pwn IP-control plan")
        for value in (
            self.baseline_recipe_sha256,
            self.baseline_evaluation_sha256,
            self.original_payload_sha256,
            self.parent_crash_recipe_sha256,
            self.parent_crash_evaluation_sha256,
        ):
            if type(value) is not str or _SHA256.fullmatch(value) is None:
                raise ValueError("invalid Pwn IP-control plan binding")
        if (
            type(self.original_payload_size_bytes) is not int
            or not 1
            <= self.original_payload_size_bytes
            <= PWN_RUNTIME_SNAPSHOT_V1_MAX_PAYLOAD_BYTES
        ):
            raise ValueError("invalid Pwn IP-control plan payload size")
        for target, payload in zip(self.targets, self.payloads, strict=True):
            if (
                type(target) is not int
                or target < PWN_IP_CONTROL_TARGET_PREFIX
                or target
                > (
                    PWN_IP_CONTROL_TARGET_PREFIX
                    | PWN_IP_CONTROL_TARGET_MASK
                )
                or type(payload) is not bytes
            ):
                raise ValueError("invalid Pwn IP-control plan target")
        if any(
            len(payload) != self.original_payload_size_bytes
            for payload in self.payloads
        ):
            raise ValueError("invalid Pwn IP-control plan variant size")

    def content_dict(self) -> dict[str, object]:
        """Return the raw-free, replayable experiment recipe."""

        return {
            "binding": {
                "baseline_evaluation_sha256": (
                    self.baseline_evaluation_sha256
                ),
                "baseline_recipe_sha256": self.baseline_recipe_sha256,
                "controlled_offset": self.controlled_offset,
                "controlled_width_bytes": PWN_IP_CONTROL_WIDTH_BYTES,
                "derivation_seed_sha256": self.derivation_seed_sha256,
                "original_payload_sha256": (
                    self.original_payload_sha256
                ),
                "original_payload_size_bytes": (
                    self.original_payload_size_bytes
                ),
                "parent_crash_evaluation_sha256": (
                    self.parent_crash_evaluation_sha256
                ),
                "parent_crash_recipe_sha256": (
                    self.parent_crash_recipe_sha256
                ),
            },
            "contract": {
                "fingerprint": PWN_IP_CONTROL_CONTRACT_FINGERPRINT,
                "id": PWN_IP_CONTROL_CONTRACT_ID,
                "version": PWN_IP_CONTROL_CONTRACT_VERSION,
            },
            "derivation_algorithm": (
                _PLAN_DERIVATION_ALGORITHM
            ),
            "replays": [
                {
                    "ordinal": ordinal,
                    "payload_sha256": hashlib.sha256(payload).hexdigest(),
                    "payload_size_bytes": len(payload),
                    "target_value_sha256": hashlib.sha256(
                        target.to_bytes(
                            PWN_IP_CONTROL_WIDTH_BYTES,
                            "little",
                        )
                    ).hexdigest(),
                }
                for ordinal, (target, payload) in enumerate(
                    zip(self.targets, self.payloads, strict=True),
                    start=1,
                )
            ],
            "schema_version": PWN_IP_CONTROL_SCHEMA_VERSION,
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


def validate_pwn_ip_control_plan_document(
    value: object,
) -> dict[str, object]:
    """Validate one raw-free persisted plan without trusting its self-hash."""

    if type(value) is not dict or set(value) != _PLAN_KEYS:
        raise ValueError("invalid Pwn IP-control plan schema")
    binding = value.get("binding")
    contract = value.get("contract")
    replays = value.get("replays")
    supplied = value.get("recipe_sha256")
    if (
        type(binding) is not dict
        or set(binding) != _PLAN_BINDING_KEYS
        or type(contract) is not dict
        or set(contract) != _CONTRACT_KEYS
        or contract
        != {
            "fingerprint": PWN_IP_CONTROL_CONTRACT_FINGERPRINT,
            "id": PWN_IP_CONTROL_CONTRACT_ID,
            "version": PWN_IP_CONTROL_CONTRACT_VERSION,
        }
        or value.get("schema_version")
        != PWN_IP_CONTROL_SCHEMA_VERSION
        or value.get("derivation_algorithm")
        != _PLAN_DERIVATION_ALGORITHM
        or type(replays) is not list
        or len(replays) != PWN_IP_CONTROL_REPLAY_COUNT
        or type(supplied) is not str
        or _SHA256.fullmatch(supplied) is None
    ):
        raise ValueError("invalid Pwn IP-control plan schema")
    for name in (
        "baseline_evaluation_sha256",
        "baseline_recipe_sha256",
        "derivation_seed_sha256",
        "original_payload_sha256",
        "parent_crash_evaluation_sha256",
        "parent_crash_recipe_sha256",
    ):
        item = binding.get(name)
        if type(item) is not str or _SHA256.fullmatch(item) is None:
            raise ValueError("invalid Pwn IP-control plan binding")
    offset = binding.get("controlled_offset")
    size = binding.get("original_payload_size_bytes")
    if (
        type(offset) is not int
        or offset < 0
        or binding.get("controlled_width_bytes")
        != PWN_IP_CONTROL_WIDTH_BYTES
        or type(size) is not int
        or not 1 <= size <= PWN_RUNTIME_SNAPSHOT_V1_MAX_PAYLOAD_BYTES
        or offset + PWN_IP_CONTROL_WIDTH_BYTES > size
    ):
        raise ValueError("invalid Pwn IP-control plan offset")
    seen_payloads: set[str] = set()
    seen_targets: set[str] = set()
    for ordinal, replay in enumerate(replays, start=1):
        if (
            type(replay) is not dict
            or set(replay) != _PLAN_REPLAY_KEYS
            or replay.get("ordinal") != ordinal
            or replay.get("payload_size_bytes") != size
        ):
            raise ValueError("invalid Pwn IP-control plan replay")
        payload_sha = replay.get("payload_sha256")
        target_sha = replay.get("target_value_sha256")
        if (
            type(payload_sha) is not str
            or _SHA256.fullmatch(payload_sha) is None
            or type(target_sha) is not str
            or _SHA256.fullmatch(target_sha) is None
            or payload_sha in seen_payloads
            or target_sha in seen_targets
        ):
            raise ValueError("invalid Pwn IP-control plan replay")
        seen_payloads.add(payload_sha)
        seen_targets.add(target_sha)
    content = dict(value)
    del content["recipe_sha256"]
    if (
        hashlib.sha256(_canonical_json_bytes(content)).hexdigest()
        != supplied
    ):
        raise ValueError("Pwn IP-control plan recipe hash mismatch")
    return value


@dataclass(frozen=True, slots=True)
class PwnIpControlEvidenceCommitment:
    capability_attestation_artifact_id: str
    capability_attestation_sha256: str
    recipe_sha256: str
    evaluation_sha256: str
    receipt_sha256: str
    payload_artifact_id: str
    payload_sha256: str
    payload_size_bytes: int
    stdout_artifact_id: str
    stdout_artifact_sha256: str
    stdout_artifact_size_bytes: int

    def __post_init__(self) -> None:
        for value in (
            self.recipe_sha256,
            self.evaluation_sha256,
            self.receipt_sha256,
            self.capability_attestation_sha256,
            self.payload_sha256,
            self.stdout_artifact_sha256,
        ):
            if type(value) is not str or _SHA256.fullmatch(value) is None:
                raise ValueError("invalid Pwn IP-control commitment hash")
        for value in (
            self.capability_attestation_artifact_id,
            self.payload_artifact_id,
            self.stdout_artifact_id,
        ):
            if (
                type(value) is not str
                or _IDENTIFIER.fullmatch(value) is None
            ):
                raise ValueError(
                    "invalid Pwn IP-control commitment artifact"
                )
        if (
            type(self.payload_size_bytes) is not int
            or not 1
            <= self.payload_size_bytes
            <= PWN_RUNTIME_SNAPSHOT_V1_MAX_PAYLOAD_BYTES
            or type(self.stdout_artifact_size_bytes) is not int
            or not 1
            <= self.stdout_artifact_size_bytes
            <= PWN_RUNTIME_SNAPSHOT_V1_MAX_DOCUMENT_BYTES
        ):
            raise ValueError("invalid Pwn IP-control commitment size")

    def to_dict(self) -> dict[str, object]:
        return {
            key: getattr(self, key) for key in sorted(_EVIDENCE_KEYS)
        }

    @classmethod
    def from_dict(
        cls,
        value: object,
    ) -> "PwnIpControlEvidenceCommitment":
        if type(value) is not dict or set(value) != _EVIDENCE_KEYS:
            raise ValueError("invalid Pwn IP-control commitment schema")
        return cls(**value)


@dataclass(frozen=True, slots=True)
class PwnIpControlReplayCommitment(PwnIpControlEvidenceCommitment):
    ordinal: int
    target_value_sha256: str

    def __post_init__(self) -> None:
        PwnIpControlEvidenceCommitment.__post_init__(self)
        if (
            type(self.ordinal) is not int
            or not 1 <= self.ordinal <= PWN_IP_CONTROL_REPLAY_COUNT
            or type(self.target_value_sha256) is not str
            or _SHA256.fullmatch(self.target_value_sha256) is None
        ):
            raise ValueError("invalid Pwn IP-control replay commitment")

    def to_dict(self) -> dict[str, object]:
        value = super().to_dict()
        value.update(
            {
                "ordinal": self.ordinal,
                "target_value_sha256": self.target_value_sha256,
            }
        )
        return value

    @classmethod
    def from_dict(
        cls,
        value: object,
    ) -> "PwnIpControlReplayCommitment":
        if type(value) is not dict or set(value) != _REPLAY_KEYS:
            raise ValueError(
                "invalid Pwn IP-control replay commitment schema"
            )
        return cls(**value)


@dataclass(frozen=True, slots=True)
class PwnIpControlResult:
    status: PwnIpControlStatus
    reason_code: str
    source_manifest_sha256: str
    source_sha256: str
    source_size_bytes: int
    parent_crash_recipe_sha256: str
    parent_crash_evaluation_sha256: str
    controlled_offset: int | None
    derivation_seed_sha256: str | None
    plan_recipe_sha256: str | None
    baseline: PwnIpControlEvidenceCommitment
    replays: tuple[PwnIpControlReplayCommitment, ...]

    def __post_init__(self) -> None:
        if type(self.status) is not PwnIpControlStatus:
            raise ValueError("invalid Pwn IP-control result status")
        if (
            self.status is PwnIpControlStatus.PROVEN
            and self.reason_code != _PROVEN_REASON
        ) or (
            self.status is PwnIpControlStatus.UNVERIFIABLE
            and self.reason_code not in _UNVERIFIABLE_REASONS
        ):
            raise ValueError("invalid Pwn IP-control result reason")
        for value in (
            self.source_manifest_sha256,
            self.source_sha256,
            self.parent_crash_recipe_sha256,
            self.parent_crash_evaluation_sha256,
        ):
            if type(value) is not str or _SHA256.fullmatch(value) is None:
                raise ValueError("invalid Pwn IP-control result hash")
        if (
            type(self.source_size_bytes) is not int
            or not 1
            <= self.source_size_bytes
            <= PWN_RUNTIME_SNAPSHOT_V1_MAX_SOURCE_BYTES
            or type(self.baseline)
            is not PwnIpControlEvidenceCommitment
            or type(self.replays) is not tuple
            or len(self.replays) > PWN_IP_CONTROL_REPLAY_COUNT
            or tuple(item.ordinal for item in self.replays)
            != tuple(range(1, len(self.replays) + 1))
        ):
            raise ValueError("invalid Pwn IP-control result binding")
        if self.controlled_offset is not None and (
            type(self.controlled_offset) is not int
            or self.controlled_offset < 0
        ):
            raise ValueError("invalid Pwn IP-control controlled offset")
        if self.derivation_seed_sha256 is not None and (
            type(self.derivation_seed_sha256) is not str
            or _SHA256.fullmatch(self.derivation_seed_sha256) is None
        ):
            raise ValueError("invalid Pwn IP-control derivation seed")
        if self.plan_recipe_sha256 is not None and (
            type(self.plan_recipe_sha256) is not str
            or _SHA256.fullmatch(self.plan_recipe_sha256) is None
        ):
            raise ValueError("invalid Pwn IP-control plan recipe hash")
        if len(
            {
                self.controlled_offset is None,
                self.derivation_seed_sha256 is None,
                self.plan_recipe_sha256 is None,
            }
        ) != 1:
            raise ValueError("incomplete Pwn IP-control plan binding")
        if self.controlled_offset is not None and (
            self.controlled_offset + PWN_IP_CONTROL_WIDTH_BYTES
            > self.baseline.payload_size_bytes
        ):
            raise ValueError("Pwn IP-control offset exceeds payload")
        if self.status is PwnIpControlStatus.PROVEN and (
            self.controlled_offset is None
            or self.derivation_seed_sha256 is None
            or self.plan_recipe_sha256 is None
            or len(self.replays) != PWN_IP_CONTROL_REPLAY_COUNT
        ):
            raise ValueError("incomplete proven Pwn IP-control result")
        self.canonical_bytes()

    @property
    def instruction_pointer_control_proven(self) -> bool:
        return self.status is PwnIpControlStatus.PROVEN

    @property
    def evidence_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def to_dict(self) -> dict[str, object]:
        proven = self.instruction_pointer_control_proven
        return {
            "authorities": {
                **_AUTHORITIES_FALSE,
                "instruction_pointer_control_proven": proven,
                "primitive_proven": proven,
            },
            "baseline": self.baseline.to_dict(),
            "binding": {
                "controlled_offset": self.controlled_offset,
                "controlled_width_bytes": PWN_IP_CONTROL_WIDTH_BYTES,
                "derivation_seed_sha256": self.derivation_seed_sha256,
                "parent_crash_evaluation_sha256": (
                    self.parent_crash_evaluation_sha256
                ),
                "parent_crash_recipe_sha256": (
                    self.parent_crash_recipe_sha256
                ),
                "plan_recipe_sha256": self.plan_recipe_sha256,
                "source_manifest_sha256": self.source_manifest_sha256,
                "source_sha256": self.source_sha256,
                "source_size_bytes": self.source_size_bytes,
            },
            "contract": {
                "fingerprint": PWN_IP_CONTROL_CONTRACT_FINGERPRINT,
                "id": PWN_IP_CONTROL_CONTRACT_ID,
                "version": PWN_IP_CONTROL_CONTRACT_VERSION,
            },
            "reason_code": self.reason_code,
            "replays": [item.to_dict() for item in self.replays],
            "schema_version": PWN_IP_CONTROL_SCHEMA_VERSION,
            "status": self.status.value,
        }

    def canonical_bytes(self) -> bytes:
        payload = _canonical_json_bytes(self.to_dict())
        if len(payload) > PWN_IP_CONTROL_MAX_RESULT_BYTES:
            raise ValueError("Pwn IP-control result exceeds byte limit")
        return payload

    @classmethod
    def from_dict(cls, value: object) -> "PwnIpControlResult":
        if type(value) is not dict or set(value) != _RESULT_KEYS:
            raise ValueError("invalid Pwn IP-control result schema")
        contract = value["contract"]
        binding = value["binding"]
        authorities = value["authorities"]
        replays = value["replays"]
        if (
            type(contract) is not dict
            or set(contract) != _CONTRACT_KEYS
            or contract
            != {
                "fingerprint": PWN_IP_CONTROL_CONTRACT_FINGERPRINT,
                "id": PWN_IP_CONTROL_CONTRACT_ID,
                "version": PWN_IP_CONTROL_CONTRACT_VERSION,
            }
            or type(binding) is not dict
            or set(binding) != _BINDING_KEYS
            or binding["controlled_width_bytes"]
            != PWN_IP_CONTROL_WIDTH_BYTES
            or type(authorities) is not dict
            or set(authorities) != _AUTHORITY_KEYS
            or value["schema_version"] != PWN_IP_CONTROL_SCHEMA_VERSION
            or type(replays) is not list
        ):
            raise ValueError("invalid Pwn IP-control result schema")
        try:
            result = cls(
                status=PwnIpControlStatus(value["status"]),
                reason_code=value["reason_code"],
                source_manifest_sha256=binding[
                    "source_manifest_sha256"
                ],
                source_sha256=binding["source_sha256"],
                source_size_bytes=binding["source_size_bytes"],
                parent_crash_recipe_sha256=binding[
                    "parent_crash_recipe_sha256"
                ],
                parent_crash_evaluation_sha256=binding[
                    "parent_crash_evaluation_sha256"
                ],
                controlled_offset=binding["controlled_offset"],
                derivation_seed_sha256=binding[
                    "derivation_seed_sha256"
                ],
                plan_recipe_sha256=binding["plan_recipe_sha256"],
                baseline=PwnIpControlEvidenceCommitment.from_dict(
                    value["baseline"]
                ),
                replays=tuple(
                    PwnIpControlReplayCommitment.from_dict(item)
                    for item in replays
                ),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError(
                "invalid Pwn IP-control result schema"
            ) from error
        if value != result.to_dict():
            raise ValueError(
                "Pwn IP-control result is not reconstructable"
            )
        return result


def _receipt_sha256(receipt: PwnRuntimeSnapshotReceiptMetadata) -> str:
    return hashlib.sha256(
        _canonical_json_bytes(receipt.to_dict())
    ).hexdigest()


def _snapshot_receipt_valid(
    recipe: PwnRuntimeSnapshotRecipe,
    evaluation: PwnRuntimeSnapshotGateEvaluation,
    receipt: PwnRuntimeSnapshotReceiptMetadata,
) -> bool:
    """Rebuild the clean-run provenance omitted from semantic observations."""

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


def _evidence_commitment(
    evidence: PwnIpControlReplayEvidence,
) -> PwnIpControlEvidenceCommitment:
    stdout_id = evidence.receipt.stdout_artifact_id
    stdout_sha = evidence.receipt.stdout_artifact_sha256
    stdout_size = evidence.receipt.stdout_artifact_size_bytes
    if (
        type(stdout_id) is not str
        or type(stdout_sha) is not str
        or type(stdout_size) is not int
        or stdout_size < 1
    ):
        # A typed receipt can describe a failed transport without stdout.
        # Such evidence cannot enter this primitive oracle at all.
        raise PwnIpControlEvidenceError("durable_stdout_unavailable")
    try:
        return PwnIpControlEvidenceCommitment(
            capability_attestation_artifact_id=(
                evidence.receipt.capability_attestation_artifact_id
            ),
            capability_attestation_sha256=(
                evidence.receipt.capability_attestation_sha256
            ),
            recipe_sha256=evidence.recipe.recipe_sha256,
            evaluation_sha256=evidence.evaluation.evidence_sha256,
            receipt_sha256=_receipt_sha256(evidence.receipt),
            payload_artifact_id=evidence.recipe.payload_artifact_id,
            payload_sha256=evidence.recipe.payload_sha256,
            payload_size_bytes=evidence.recipe.payload_size_bytes,
            stdout_artifact_id=stdout_id,
            stdout_artifact_sha256=stdout_sha,
            stdout_artifact_size_bytes=stdout_size,
        )
    except ValueError as error:
        raise PwnIpControlEvidenceError(
            "invalid_evidence_commitment"
        ) from error


def _replay_commitment(
    evidence: PwnIpControlReplayEvidence,
    target: int,
) -> PwnIpControlReplayCommitment:
    base = _evidence_commitment(evidence)
    return PwnIpControlReplayCommitment(
        **base.to_dict(),
        ordinal=evidence.ordinal,
        target_value_sha256=hashlib.sha256(
            target.to_bytes(PWN_IP_CONTROL_WIDTH_BYTES, "little")
        ).hexdigest(),
    )


def _strict_maps_ranges(data: bytes) -> tuple[tuple[int, int], ...]:
    if type(data) is not bytes or not data or not data.endswith(b"\n"):
        raise ValueError("invalid proc maps")
    ranges: list[tuple[int, int]] = []
    previous_end = 0
    for line in data.splitlines():
        if not line or len(line) > 8192:
            raise ValueError("invalid proc maps")
        match = _MAP_LINE.fullmatch(line)
        if match is None:
            raise ValueError("invalid proc maps")
        start = int(match.group("start"), 16)
        end = int(match.group("end"), 16)
        offset = int(match.group("offset"), 16)
        inode = int(match.group("inode"), 10)
        if (
            not 0 <= start < end <= (1 << 64)
            or start < previous_end
            or offset > (1 << 64) - 1
            or inode > (1 << 64) - 1
        ):
            raise ValueError("invalid proc maps")
        ranges.append((start, end))
        previous_end = end
    if not ranges:
        raise ValueError("invalid proc maps")
    return tuple(ranges)


def _mapped(address: int, ranges: tuple[tuple[int, int], ...]) -> bool:
    return any(start <= address < end for start, end in ranges)


def _all_offsets(data: bytes, needle: bytes) -> tuple[int, ...]:
    offsets: list[int] = []
    cursor = 0
    while True:
        offset = data.find(needle, cursor)
        if offset < 0:
            return tuple(offsets)
        offsets.append(offset)
        cursor = offset + 1


def _seed_for(
    recipe: PwnRuntimeSnapshotRecipe,
    evaluation: PwnRuntimeSnapshotGateEvaluation,
    payload: bytes,
) -> str:
    return hashlib.sha256(
        _canonical_json_bytes(
            {
                "domain": "ctfos.pwn.ip_control.plan.v1",
                "baseline_evaluation_sha256": (
                    evaluation.evidence_sha256
                ),
                "baseline_recipe_sha256": recipe.recipe_sha256,
                "original_payload_sha256": (
                    hashlib.sha256(payload).hexdigest()
                ),
                "parent_crash_evaluation_sha256": (
                    recipe.parent_crash_evaluation_sha256
                ),
                "parent_crash_recipe_sha256": (
                    recipe.parent_crash_recipe_sha256
                ),
                "source_manifest_sha256": (
                    recipe.source_manifest_sha256
                ),
                "source_sha256": recipe.source_sha256,
            }
        )
    ).hexdigest()


def _derive_target(
    seed_sha256: str,
    ordinal: int,
    attempt: int,
) -> int:
    digest = hashlib.sha256(
        b"ctfos.pwn.ip_control.target.v1\x00"
        + bytes.fromhex(seed_sha256)
        + ordinal.to_bytes(1, "big")
        + attempt.to_bytes(2, "big")
    ).digest()
    return PWN_IP_CONTROL_TARGET_PREFIX | (
        int.from_bytes(digest[:5], "big") & PWN_IP_CONTROL_TARGET_MASK
    )


class PwnIpControlPlanError(ValueError):
    """Stable inapplicability reason for deterministic plan construction."""

    def __init__(self, code: str) -> None:
        if code not in _UNVERIFIABLE_REASONS:
            raise ValueError("unknown Pwn IP-control plan error")
        super().__init__(code)
        self.code = code


class PwnIpControlEvidenceError(ValueError):
    """Stable structural rejection before a result can be committed."""

    _CODES = frozenset(
        {
            "durable_stdout_unavailable",
            "invalid_evidence_commitment",
        }
    )

    def __init__(self, code: str) -> None:
        if code not in self._CODES:
            raise ValueError("unknown Pwn IP-control evidence error")
        super().__init__(code)
        self.code = code


def derive_pwn_ip_control_plan(
    recipe: PwnRuntimeSnapshotRecipe,
    evaluation: PwnRuntimeSnapshotGateEvaluation,
    original_payload: bytes,
) -> PwnIpControlPlan:
    """Derive three exact variants without granting any authority."""

    if (
        type(recipe) is not PwnRuntimeSnapshotRecipe
        or type(evaluation) is not PwnRuntimeSnapshotGateEvaluation
        or type(original_payload) is not bytes
    ):
        raise TypeError("invalid Pwn IP-control plan input")
    if not evaluation.captured or evaluation.semantic_result is None:
        raise PwnIpControlPlanError("baseline_not_captured")
    semantic = evaluation.semantic_result
    if (
        recipe.expected_signal_number != PWN_IP_CONTROL_EXPECTED_SIGNAL
        or semantic.expected_signal_number
        != PWN_IP_CONTROL_EXPECTED_SIGNAL
    ):
        raise PwnIpControlPlanError("baseline_signal_not_sigsegv")
    if (
        len(original_payload) != recipe.payload_size_bytes
        or hashlib.sha256(original_payload).hexdigest()
        != recipe.payload_sha256
        or semantic.payload_sha256 != recipe.payload_sha256
        or semantic.payload_size_bytes != recipe.payload_size_bytes
    ):
        raise PwnIpControlPlanError(
            "baseline_payload_binding_mismatch"
        )
    if semantic.registers is None or semantic.maps is None:
        raise PwnIpControlPlanError("baseline_not_captured")
    try:
        ranges = _strict_maps_ranges(semantic.maps.data)
    except ValueError as error:
        raise PwnIpControlPlanError("baseline_maps_invalid") from error
    rip_hex = dict(semantic.registers.values)["rip"]
    rip_bytes = int(rip_hex, 16).to_bytes(
        PWN_IP_CONTROL_WIDTH_BYTES,
        "little",
    )
    offsets = _all_offsets(original_payload, rip_bytes)
    if not offsets:
        raise PwnIpControlPlanError("rip_not_payload_derived")
    if len(offsets) != 1:
        raise PwnIpControlPlanError("rip_offset_ambiguous")
    controlled_offset = offsets[0]
    seed = _seed_for(recipe, evaluation, original_payload)
    targets: list[int] = []
    payloads: list[bytes] = []
    for ordinal in range(1, PWN_IP_CONTROL_REPLAY_COUNT + 1):
        selected: int | None = None
        for attempt in range(PWN_IP_CONTROL_MAX_DERIVATION_ATTEMPTS):
            target = _derive_target(seed, ordinal, attempt)
            encoded = target.to_bytes(
                PWN_IP_CONTROL_WIDTH_BYTES,
                "little",
            )
            if (
                target not in targets
                and not _mapped(target, ranges)
                and encoded not in original_payload
            ):
                selected = target
                break
        if selected is None:
            raise PwnIpControlPlanError(
                "target_derivation_exhausted"
            )
        encoded = selected.to_bytes(
            PWN_IP_CONTROL_WIDTH_BYTES,
            "little",
        )
        variant = (
            original_payload[:controlled_offset]
            + encoded
            + original_payload[
                controlled_offset + PWN_IP_CONTROL_WIDTH_BYTES :
            ]
        )
        if _all_offsets(variant, encoded) != (controlled_offset,):
            raise PwnIpControlPlanError("target_bytes_not_unique")
        targets.append(selected)
        payloads.append(variant)
    return PwnIpControlPlan(
        controlled_offset=controlled_offset,
        derivation_seed_sha256=seed,
        baseline_recipe_sha256=recipe.recipe_sha256,
        baseline_evaluation_sha256=evaluation.evidence_sha256,
        original_payload_sha256=hashlib.sha256(
            original_payload
        ).hexdigest(),
        original_payload_size_bytes=len(original_payload),
        parent_crash_recipe_sha256=recipe.parent_crash_recipe_sha256,
        parent_crash_evaluation_sha256=(
            recipe.parent_crash_evaluation_sha256
        ),
        targets=tuple(targets),
        payloads=tuple(payloads),
    )


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


def _parent_crash_binding_valid(
    parent_recipe: PwnCrashRecipe,
    parent_evaluation: PwnCrashGateEvaluation,
    baseline: PwnIpControlReplayEvidence,
) -> bool:
    semantic = parent_evaluation.semantic_evaluation
    if semantic is None:
        return False
    signal_counts = semantic.positive_signal_counts
    maximum = max((count for _signal, count in signal_counts), default=0)
    expected_signals = tuple(
        signal
        for signal, count in signal_counts
        if count == maximum and count >= 2
    )
    recipe = baseline.recipe
    return (
        semantic.recipe_sha256 == parent_recipe.recipe_sha256
        and semantic.source_manifest_sha256
        == parent_recipe.source_manifest_sha256
        and semantic.source_sha256 == parent_recipe.source_sha256
        and semantic.source_size_bytes == parent_recipe.source_size_bytes
        and semantic.poc_sha256 == parent_recipe.payload_sha256
        and semantic.poc_size_bytes == parent_recipe.payload_size_bytes
        and recipe.parent_experiment_id == parent_recipe.experiment_id
        and recipe.primary_elf_locator
        == parent_recipe.primary_elf_locator
        and recipe.source_manifest_sha256
        == parent_recipe.source_manifest_sha256
        and recipe.source_sha256 == parent_recipe.source_sha256
        and recipe.source_size_bytes == parent_recipe.source_size_bytes
        and recipe.payload_artifact_id
        == parent_recipe.payload_artifact_id
        and recipe.payload_source_run_id
        == parent_recipe.payload_source_run_id
        and recipe.payload_artifact_locator
        == parent_recipe.payload_artifact_locator
        and recipe.payload_sha256 == parent_recipe.payload_sha256
        and recipe.payload_size_bytes
        == parent_recipe.payload_size_bytes
        and recipe.configuration_epoch
        == parent_recipe.configuration_epoch
        and recipe.image_reference == parent_recipe.image_reference
        and recipe.image_digest == parent_recipe.image_digest
        and recipe.parent_crash_recipe_sha256
        == parent_recipe.recipe_sha256
        and recipe.parent_crash_evaluation_sha256
        == parent_evaluation.evidence_sha256
        and expected_signals
        == (PWN_IP_CONTROL_EXPECTED_SIGNAL,)
    )


def _result(
    *,
    baseline: PwnIpControlReplayEvidence,
    baseline_commitment: PwnIpControlEvidenceCommitment,
    reason: str,
    plan: PwnIpControlPlan | None,
    replay_commitments: tuple[PwnIpControlReplayCommitment, ...],
) -> PwnIpControlResult:
    proven = reason == _PROVEN_REASON
    return PwnIpControlResult(
        status=(
            PwnIpControlStatus.PROVEN
            if proven
            else PwnIpControlStatus.UNVERIFIABLE
        ),
        reason_code=reason,
        source_manifest_sha256=baseline.recipe.source_manifest_sha256,
        source_sha256=baseline.recipe.source_sha256,
        source_size_bytes=baseline.recipe.source_size_bytes,
        parent_crash_recipe_sha256=(
            baseline.recipe.parent_crash_recipe_sha256
        ),
        parent_crash_evaluation_sha256=(
            baseline.recipe.parent_crash_evaluation_sha256
        ),
        controlled_offset=(
            plan.controlled_offset if plan is not None else None
        ),
        derivation_seed_sha256=(
            plan.derivation_seed_sha256 if plan is not None else None
        ),
        plan_recipe_sha256=(
            plan.recipe_sha256 if plan is not None else None
        ),
        baseline=baseline_commitment,
        replays=replay_commitments,
    )


def evaluate_pwn_ip_control(
    *,
    parent_crash_recipe: PwnCrashRecipe,
    parent_crash_evaluation: PwnCrashGateEvaluation,
    baseline: PwnIpControlReplayEvidence,
    replays: tuple[PwnIpControlReplayEvidence, ...],
) -> PwnIpControlResult:
    """Recompute four exact gates and prove or reject RIP control."""

    if (
        type(parent_crash_recipe) is not PwnCrashRecipe
        or type(parent_crash_evaluation)
        is not PwnCrashGateEvaluation
        or type(baseline) is not PwnIpControlReplayEvidence
    ):
        raise TypeError("exact Pwn crash and replay evidence is required")
    if baseline.ordinal != 0:
        raise ValueError("baseline replay ordinal must be zero")
    if (
        type(replays) is not tuple
        or len(replays) != PWN_IP_CONTROL_REPLAY_COUNT
        or tuple(item.ordinal for item in replays)
        != tuple(range(1, PWN_IP_CONTROL_REPLAY_COUNT + 1))
        or any(
            type(item) is not PwnIpControlReplayEvidence
            for item in replays
        )
    ):
        raise ValueError("three ordered replay inputs are required")
    baseline_commitment = _evidence_commitment(baseline)
    recomputed_baseline = evaluate_pwn_runtime_snapshot_gate(
        baseline.recipe,
        stdout_payload=baseline.stdout_payload,
        receipt=baseline.receipt,
    )
    if recomputed_baseline != baseline.evaluation:
        return _result(
            baseline=baseline,
            baseline_commitment=baseline_commitment,
            reason="baseline_gate_changed",
            plan=None,
            replay_commitments=(),
        )
    if (
        parent_crash_evaluation.verdict
        is not PwnCrashV1Verdict.CONFIRMED
        or not parent_crash_evaluation.passed
        or parent_crash_evaluation.semantic_evaluation is None
    ):
        return _result(
            baseline=baseline,
            baseline_commitment=baseline_commitment,
            reason="parent_crash_not_confirmed",
            plan=None,
            replay_commitments=(),
        )
    if not _parent_crash_binding_valid(
        parent_crash_recipe,
        parent_crash_evaluation,
        baseline,
    ):
        return _result(
            baseline=baseline,
            baseline_commitment=baseline_commitment,
            reason="parent_crash_binding_mismatch",
            plan=None,
            replay_commitments=(),
        )
    if not _snapshot_receipt_valid(
        baseline.recipe,
        recomputed_baseline,
        baseline.receipt,
    ):
        return _result(
            baseline=baseline,
            baseline_commitment=baseline_commitment,
            reason="baseline_receipt_binding_mismatch",
            plan=None,
            replay_commitments=(),
        )
    try:
        plan = derive_pwn_ip_control_plan(
            baseline.recipe,
            recomputed_baseline,
            baseline.payload,
        )
    except PwnIpControlPlanError as error:
        return _result(
            baseline=baseline,
            baseline_commitment=baseline_commitment,
            reason=error.code,
            plan=None,
            replay_commitments=(),
        )

    commitments: list[PwnIpControlReplayCommitment] = []
    identities: dict[str, set[str]] = {
        "payload_artifact_id": {
            baseline.recipe.payload_artifact_id
        },
        "capability_attestation_artifact_id": {
            baseline.receipt.capability_attestation_artifact_id
        },
        "payload_artifact_locator": {
            baseline.recipe.payload_artifact_locator
        },
        "payload_source_run_id": {
            baseline.recipe.payload_source_run_id
        },
        "receipt_id": {baseline.receipt.receipt_id},
        "run_id": {baseline.receipt.run_id},
        "request_sha256": {baseline.receipt.request_sha256},
        "execution_contract_sha256": {
            baseline.receipt.execution_contract_sha256
        },
        "stdout_artifact_id": {
            baseline.receipt.stdout_artifact_id or ""
        },
        "stderr_artifact_id": {
            baseline.receipt.stderr_artifact_id
        },
    }
    for replay, target, expected_payload in zip(
        replays,
        plan.targets,
        plan.payloads,
        strict=True,
    ):
        commitment = _replay_commitment(replay, target)
        commitments.append(commitment)
        if not _same_runtime_binding(baseline.recipe, replay.recipe):
            return _result(
                baseline=baseline,
                baseline_commitment=baseline_commitment,
                reason="cross_replay_binding_mismatch",
                plan=plan,
                replay_commitments=tuple(commitments),
            )
        current_identities: dict[str, str] = {
            "payload_artifact_id": replay.recipe.payload_artifact_id,
            "capability_attestation_artifact_id": (
                replay.receipt.capability_attestation_artifact_id
            ),
            "payload_artifact_locator": (
                replay.recipe.payload_artifact_locator
            ),
            "payload_source_run_id": (
                replay.recipe.payload_source_run_id
            ),
            "receipt_id": replay.receipt.receipt_id,
            "run_id": replay.receipt.run_id,
            "request_sha256": replay.receipt.request_sha256,
            "execution_contract_sha256": (
                replay.receipt.execution_contract_sha256
            ),
            "stdout_artifact_id": (
                replay.receipt.stdout_artifact_id or ""
            ),
            "stderr_artifact_id": replay.receipt.stderr_artifact_id,
        }
        if any(
            value in identities[name]
            for name, value in current_identities.items()
        ):
            return _result(
                baseline=baseline,
                baseline_commitment=baseline_commitment,
                reason="replay_identity_reused",
                plan=plan,
                replay_commitments=tuple(commitments),
            )
        for name, value in current_identities.items():
            identities[name].add(value)
        if (
            replay.payload != expected_payload
            or len(replay.payload) != len(baseline.payload)
            or replay.payload[: plan.controlled_offset]
            != baseline.payload[: plan.controlled_offset]
            or replay.payload[
                plan.controlled_offset + PWN_IP_CONTROL_WIDTH_BYTES :
            ]
            != baseline.payload[
                plan.controlled_offset + PWN_IP_CONTROL_WIDTH_BYTES :
            ]
        ):
            return _result(
                baseline=baseline,
                baseline_commitment=baseline_commitment,
                reason="replay_payload_not_exact_variant",
                plan=plan,
                replay_commitments=tuple(commitments),
            )
        if (
            replay.recipe.payload_sha256
            != hashlib.sha256(replay.payload).hexdigest()
            or replay.recipe.payload_size_bytes != len(replay.payload)
        ):
            return _result(
                baseline=baseline,
                baseline_commitment=baseline_commitment,
                reason="replay_payload_binding_mismatch",
                plan=plan,
                replay_commitments=tuple(commitments),
            )
        target_bytes = target.to_bytes(
            PWN_IP_CONTROL_WIDTH_BYTES,
            "little",
        )
        if _all_offsets(replay.payload, target_bytes) != (
            plan.controlled_offset,
        ):
            return _result(
                baseline=baseline,
                baseline_commitment=baseline_commitment,
                reason="target_bytes_not_unique",
                plan=plan,
                replay_commitments=tuple(commitments),
            )
        recomputed = evaluate_pwn_runtime_snapshot_gate(
            replay.recipe,
            stdout_payload=replay.stdout_payload,
            receipt=replay.receipt,
        )
        if recomputed != replay.evaluation:
            return _result(
                baseline=baseline,
                baseline_commitment=baseline_commitment,
                reason="replay_gate_changed",
                plan=plan,
                replay_commitments=tuple(commitments),
            )
        if not _snapshot_receipt_valid(
            replay.recipe,
            recomputed,
            replay.receipt,
        ):
            return _result(
                baseline=baseline,
                baseline_commitment=baseline_commitment,
                reason="replay_receipt_binding_mismatch",
                plan=plan,
                replay_commitments=tuple(commitments),
            )
        if not recomputed.captured or recomputed.semantic_result is None:
            return _result(
                baseline=baseline,
                baseline_commitment=baseline_commitment,
                reason="replay_not_captured",
                plan=plan,
                replay_commitments=tuple(commitments),
            )
        semantic = recomputed.semantic_result
        if semantic.registers is None or semantic.maps is None:
            return _result(
                baseline=baseline,
                baseline_commitment=baseline_commitment,
                reason="replay_not_captured",
                plan=plan,
                replay_commitments=tuple(commitments),
            )
        observed_rip = int(
            dict(semantic.registers.values)["rip"],
            16,
        )
        if observed_rip != target:
            return _result(
                baseline=baseline,
                baseline_commitment=baseline_commitment,
                reason="instruction_pointer_mismatch",
                plan=plan,
                replay_commitments=tuple(commitments),
            )
        try:
            ranges = _strict_maps_ranges(semantic.maps.data)
        except ValueError:
            return _result(
                baseline=baseline,
                baseline_commitment=baseline_commitment,
                reason="replay_maps_invalid",
                plan=plan,
                replay_commitments=tuple(commitments),
            )
        if _mapped(target, ranges):
            return _result(
                baseline=baseline,
                baseline_commitment=baseline_commitment,
                reason="target_address_mapped",
                plan=plan,
                replay_commitments=tuple(commitments),
            )
    return _result(
        baseline=baseline,
        baseline_commitment=baseline_commitment,
        reason=_PROVEN_REASON,
        plan=plan,
        replay_commitments=tuple(commitments),
    )


__all__ = [
    "PWN_IP_CONTROL_CONTRACT_FINGERPRINT",
    "PWN_IP_CONTROL_CONTRACT_ID",
    "PWN_IP_CONTROL_CONTRACT_VERSION",
    "PWN_IP_CONTROL_REPLAY_COUNT",
    "PWN_IP_CONTROL_SCHEMA_VERSION",
    "PWN_IP_CONTROL_WIDTH_BYTES",
    "PwnIpControlEvidenceCommitment",
    "PwnIpControlEvidenceError",
    "PwnIpControlPlan",
    "PwnIpControlPlanError",
    "PwnIpControlReplayCommitment",
    "PwnIpControlReplayEvidence",
    "PwnIpControlResult",
    "PwnIpControlStatus",
    "derive_pwn_ip_control_plan",
    "evaluate_pwn_ip_control",
    "pwn_ip_control_child_experiment_id",
    "pwn_ip_control_contract_descriptor",
    "validate_pwn_ip_control_plan_document",
]
