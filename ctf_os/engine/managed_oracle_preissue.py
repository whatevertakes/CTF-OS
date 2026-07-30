"""Canonical hidden-oracle contract for managed Crypto and Misc gates."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from ctf_os.store.atomic import canonical_json_bytes


MANAGED_ORACLE_PREISSUE_PROTOCOL = "managed_oracle_preissue_v1"
MANAGED_ORACLE_PREISSUE_SCHEMA_VERSION = 1
MANAGED_ORACLE_PREISSUE_STATE_KEY = "managed_oracle_preissues"
MANAGED_ORACLE_PREISSUE_MAX_HISTORY = 64
MANAGED_ORACLE_PREISSUE_MAX_MANIFEST_BYTES = 64 * 1024
MANAGED_ORACLE_PREISSUE_CRYPTO = "crypto"
MANAGED_ORACLE_PREISSUE_MISC = "misc"
MANAGED_ORACLE_PREISSUE_KINDS = frozenset(
    {
        MANAGED_ORACLE_PREISSUE_CRYPTO,
        MANAGED_ORACLE_PREISSUE_MISC,
    }
)

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_PUBLIC_KEYS = frozenset(
    {
        "schema_version",
        "protocol",
        "preissue_id",
        "kind",
        "status",
        "issuer",
        "issued_at",
        "issue_revision",
        "configuration_epoch",
        "source_manifest_sha256",
        "image_digest",
        "oracle_seal_sha256",
        "consumed_at",
        "consumed_by_builder_run_id",
        "consumed_by_experiment_id",
    }
)
_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "protocol",
        "preissue_id",
        "kind",
        "issuer",
        "issued_at",
        "issue_revision",
        "configuration_epoch",
        "source_manifest_sha256",
        "image_digest",
        "seal_nonce",
        "metadata",
        "inputs",
    }
)
_INPUT_KEYS = frozenset({"purpose", "artifact_id", "sha256", "size_bytes"})


class ManagedOraclePreissueError(ValueError):
    """Stable fail-closed rejection of a malformed or rebound preissue."""


def _safe_id(value: object, label: str) -> str:
    if type(value) is not str or _SAFE_ID.fullmatch(value) is None:
        raise ManagedOraclePreissueError(f"{label} is not a safe identifier")
    return value


def _sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ManagedOraclePreissueError(f"{label} is not a SHA-256 digest")
    return value


def _positive_revision(value: object, label: str) -> int:
    if type(value) is not int or value < 1:
        raise ManagedOraclePreissueError(f"{label} is not a positive revision")
    return value


@dataclass(frozen=True, slots=True)
class ManagedOraclePreissueInput:
    purpose: str
    artifact_id: str
    sha256: str
    size_bytes: int

    def to_dict(self) -> dict[str, object]:
        return {
            "purpose": self.purpose,
            "artifact_id": self.artifact_id,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True, slots=True)
class ManagedOraclePreissueManifest:
    preissue_id: str
    kind: str
    issued_at: str
    issue_revision: int
    configuration_epoch: int
    source_manifest_sha256: str
    image_digest: str
    seal_nonce: str
    metadata: Mapping[str, str]
    inputs: tuple[ManagedOraclePreissueInput, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": MANAGED_ORACLE_PREISSUE_SCHEMA_VERSION,
            "protocol": MANAGED_ORACLE_PREISSUE_PROTOCOL,
            "preissue_id": self.preissue_id,
            "kind": self.kind,
            "issuer": "operator",
            "issued_at": self.issued_at,
            "issue_revision": self.issue_revision,
            "configuration_epoch": self.configuration_epoch,
            "source_manifest_sha256": self.source_manifest_sha256,
            "image_digest": self.image_digest,
            "seal_nonce": self.seal_nonce,
            "metadata": dict(self.metadata),
            "inputs": [item.to_dict() for item in self.inputs],
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes).hexdigest()


def build_manifest(
    *,
    preissue_id: str,
    kind: str,
    issued_at: str,
    issue_revision: int,
    configuration_epoch: int,
    source_manifest_sha256: str,
    image_digest: str,
    seal_nonce: str,
    metadata: Mapping[str, str],
    inputs: Sequence[ManagedOraclePreissueInput],
) -> ManagedOraclePreissueManifest:
    """Build and self-validate one exact private manifest."""

    return parse_manifest(
        ManagedOraclePreissueManifest(
            preissue_id=preissue_id,
            kind=kind,
            issued_at=issued_at,
            issue_revision=issue_revision,
            configuration_epoch=configuration_epoch,
            source_manifest_sha256=source_manifest_sha256,
            image_digest=image_digest,
            seal_nonce=seal_nonce,
            metadata=dict(metadata),
            inputs=tuple(inputs),
        ).to_dict()
    )


def parse_manifest(value: object) -> ManagedOraclePreissueManifest:
    if not isinstance(value, Mapping) or frozenset(value) != _MANIFEST_KEYS:
        raise ManagedOraclePreissueError(
            "managed oracle manifest has unknown or missing fields"
        )
    if (
        value.get("schema_version")
        != MANAGED_ORACLE_PREISSUE_SCHEMA_VERSION
        or value.get("protocol") != MANAGED_ORACLE_PREISSUE_PROTOCOL
        or value.get("issuer") != "operator"
    ):
        raise ManagedOraclePreissueError(
            "managed oracle manifest protocol is invalid"
        )
    preissue_id = _safe_id(value.get("preissue_id"), "preissue id")
    kind = value.get("kind")
    if kind not in MANAGED_ORACLE_PREISSUE_KINDS:
        raise ManagedOraclePreissueError("managed oracle kind is invalid")
    issued_at = value.get("issued_at")
    if type(issued_at) is not str or not issued_at or len(issued_at) > 64:
        raise ManagedOraclePreissueError("managed oracle issue time is invalid")
    issue_revision = _positive_revision(
        value.get("issue_revision"),
        "managed oracle issue revision",
    )
    configuration_epoch = value.get("configuration_epoch")
    if type(configuration_epoch) is not int or configuration_epoch < 0:
        raise ManagedOraclePreissueError(
            "managed oracle configuration epoch is invalid"
        )
    source_manifest_sha256 = _sha256(
        value.get("source_manifest_sha256"),
        "managed oracle source manifest",
    )
    image_digest = value.get("image_digest")
    if type(image_digest) is not str or _IMAGE_DIGEST.fullmatch(image_digest) is None:
        raise ManagedOraclePreissueError(
            "managed oracle image digest is invalid"
        )
    seal_nonce = value.get("seal_nonce")
    if type(seal_nonce) is not str or _SHA256.fullmatch(seal_nonce) is None:
        raise ManagedOraclePreissueError("managed oracle nonce is invalid")
    metadata = value.get("metadata")
    if not isinstance(metadata, Mapping):
        raise ManagedOraclePreissueError("managed oracle metadata is invalid")
    expected_metadata = (
        frozenset({"mutation_id"})
        if kind == MANAGED_ORACLE_PREISSUE_CRYPTO
        else frozenset({"oracle_id", "verifier_id"})
    )
    if frozenset(metadata) != expected_metadata:
        raise ManagedOraclePreissueError(
            "managed oracle metadata has unknown or missing fields"
        )
    normalized_metadata = {
        key: _safe_id(metadata.get(key), f"managed oracle {key}")
        for key in sorted(expected_metadata)
    }
    raw_inputs = value.get("inputs")
    expected_purposes = (
        ("variant_parameters", "variant_expected_output")
        if kind == MANAGED_ORACLE_PREISSUE_CRYPTO
        else ("verifier_tool",)
    )
    if type(raw_inputs) is not list or len(raw_inputs) != len(expected_purposes):
        raise ManagedOraclePreissueError("managed oracle input count is invalid")
    inputs: list[ManagedOraclePreissueInput] = []
    artifact_ids: set[str] = set()
    for index, (raw, purpose) in enumerate(
        zip(raw_inputs, expected_purposes, strict=True),
        start=1,
    ):
        if not isinstance(raw, Mapping) or frozenset(raw) != _INPUT_KEYS:
            raise ManagedOraclePreissueError(
                f"managed oracle input {index} schema is invalid"
            )
        if raw.get("purpose") != purpose:
            raise ManagedOraclePreissueError(
                f"managed oracle input {index} purpose is invalid"
            )
        artifact_id = _safe_id(
            raw.get("artifact_id"),
            f"managed oracle input {index} artifact id",
        )
        if artifact_id in artifact_ids:
            raise ManagedOraclePreissueError(
                "managed oracle input artifact ids repeat"
            )
        artifact_ids.add(artifact_id)
        size_bytes = raw.get("size_bytes")
        if type(size_bytes) is not int or size_bytes < 0:
            raise ManagedOraclePreissueError(
                f"managed oracle input {index} size is invalid"
            )
        inputs.append(
            ManagedOraclePreissueInput(
                purpose=purpose,
                artifact_id=artifact_id,
                sha256=_sha256(
                    raw.get("sha256"),
                    f"managed oracle input {index} digest",
                ),
                size_bytes=size_bytes,
            )
        )
    return ManagedOraclePreissueManifest(
        preissue_id=preissue_id,
        kind=str(kind),
        issued_at=issued_at,
        issue_revision=issue_revision,
        configuration_epoch=configuration_epoch,
        source_manifest_sha256=source_manifest_sha256,
        image_digest=image_digest,
        seal_nonce=seal_nonce,
        metadata=normalized_metadata,
        inputs=tuple(inputs),
    )


def public_record(manifest: ManagedOraclePreissueManifest) -> dict[str, object]:
    return {
        "schema_version": MANAGED_ORACLE_PREISSUE_SCHEMA_VERSION,
        "protocol": MANAGED_ORACLE_PREISSUE_PROTOCOL,
        "preissue_id": manifest.preissue_id,
        "kind": manifest.kind,
        "status": "unused",
        "issuer": "operator",
        "issued_at": manifest.issued_at,
        "issue_revision": manifest.issue_revision,
        "configuration_epoch": manifest.configuration_epoch,
        "source_manifest_sha256": manifest.source_manifest_sha256,
        "image_digest": manifest.image_digest,
        "oracle_seal_sha256": manifest.sha256,
        "consumed_at": None,
        "consumed_by_builder_run_id": None,
        "consumed_by_experiment_id": None,
    }


def validate_public_record(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping) or frozenset(value) != _PUBLIC_KEYS:
        raise ManagedOraclePreissueError(
            "managed oracle public record has unknown or missing fields"
        )
    if (
        value.get("schema_version")
        != MANAGED_ORACLE_PREISSUE_SCHEMA_VERSION
        or value.get("protocol") != MANAGED_ORACLE_PREISSUE_PROTOCOL
        or value.get("issuer") != "operator"
        or value.get("kind") not in MANAGED_ORACLE_PREISSUE_KINDS
        or value.get("status") not in {"unused", "consumed"}
    ):
        raise ManagedOraclePreissueError(
            "managed oracle public record protocol is invalid"
        )
    _safe_id(value.get("preissue_id"), "preissue id")
    _positive_revision(value.get("issue_revision"), "preissue issue revision")
    epoch = value.get("configuration_epoch")
    if type(epoch) is not int or epoch < 0:
        raise ManagedOraclePreissueError(
            "managed oracle public epoch is invalid"
        )
    _sha256(
        value.get("source_manifest_sha256"),
        "managed oracle public source manifest",
    )
    _sha256(
        value.get("oracle_seal_sha256"),
        "managed oracle public seal",
    )
    image = value.get("image_digest")
    issued_at = value.get("issued_at")
    if (
        type(image) is not str
        or _IMAGE_DIGEST.fullmatch(image) is None
        or type(issued_at) is not str
        or not issued_at
        or len(issued_at) > 64
    ):
        raise ManagedOraclePreissueError(
            "managed oracle public pins are invalid"
        )
    consumed_fields = (
        value.get("consumed_at"),
        value.get("consumed_by_builder_run_id"),
        value.get("consumed_by_experiment_id"),
    )
    if value.get("status") == "unused":
        if any(item is not None for item in consumed_fields):
            raise ManagedOraclePreissueError(
                "unused managed oracle has consumption metadata"
            )
    else:
        consumed_at, builder_id, experiment_id = consumed_fields
        if (
            type(consumed_at) is not str
            or not consumed_at
            or len(consumed_at) > 64
        ):
            raise ManagedOraclePreissueError(
                "consumed managed oracle time is invalid"
            )
        _safe_id(builder_id, "managed oracle Builder run id")
        _safe_id(experiment_id, "managed oracle experiment id")
    return dict(value)


__all__ = [
    "MANAGED_ORACLE_PREISSUE_CRYPTO",
    "MANAGED_ORACLE_PREISSUE_KINDS",
    "MANAGED_ORACLE_PREISSUE_MAX_HISTORY",
    "MANAGED_ORACLE_PREISSUE_MAX_MANIFEST_BYTES",
    "MANAGED_ORACLE_PREISSUE_MISC",
    "MANAGED_ORACLE_PREISSUE_PROTOCOL",
    "MANAGED_ORACLE_PREISSUE_SCHEMA_VERSION",
    "MANAGED_ORACLE_PREISSUE_STATE_KEY",
    "ManagedOraclePreissueError",
    "ManagedOraclePreissueInput",
    "ManagedOraclePreissueManifest",
    "build_manifest",
    "parse_manifest",
    "public_record",
    "validate_public_record",
]
