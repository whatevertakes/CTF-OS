"""Fail-closed managed model-thread continuity contracts.

Raw provider thread identifiers never belong in canonical state or request
metadata.  This module defines the small, deterministic metadata contracts
used by both the managed orchestrator and the challenge engine.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any


THREAD_CONTINUITY_SESSION_KEY = "managed_thread_continuity_v1"
THREAD_CONTINUITY_RUN_KEY = "thread_continuity_v1"
THREAD_CONTINUITY_CONTRACT_VERSION = 2
THREAD_CONTINUITY_POLICIES = frozenset(
    {"fresh", "captain_lane", "role_lane"}
)
THREAD_CONTINUITY_ELIGIBLE_ROLES = frozenset(
    {"captain", "builder", "recon", "specialist", "extractor"}
)
THREAD_CONTINUITY_ALWAYS_FRESH_ROLES = frozenset(
    {
        "falsifier",
        "reproducer",
        "validator",
        "evidence_auditor",
    }
)
THREAD_CONTINUITY_REASON_CODES = frozenset(
    {
        "policy_fresh",
        "captain_lane_non_captain",
        "role_lane_ineligible_role",
        "proof_wave_forced_fresh",
        "no_prior_lane_run",
        "prior_lane_not_completed",
        "prior_session_mismatch",
        "prior_configuration_mismatch",
        "prior_model_mismatch",
        "prior_contract_mismatch",
        "prior_role_mismatch",
        "prior_workspace_mismatch",
        "prior_source_mismatch",
        "prior_target_mismatch",
        "prior_thread_missing",
        "prior_thread_invalid",
        "prior_thread_hash_mismatch",
        "resume_previous_completed_lane",
    }
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_THREAD_ID = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")
_SESSION_KEYS = frozenset(
    {
        "schema_version",
        "policy",
        "configuration_epoch",
        "contract_version",
        "source_manifest_sha256",
        "source_generation",
        "target_id",
        "target_generation",
        "runtime_image_digest",
        "captain_effort",
        "worker_effort",
        "models",
        "configuration_fingerprint_sha256",
    }
)
_AUDIT_KEYS = frozenset(
    {
        "schema_version",
        "policy",
        "decision",
        "reason",
        "source_run_id",
        "thread_id_sha256",
        "session_id",
        "configuration_epoch",
        "configuration_fingerprint_sha256",
        "contract_version",
        "logical_role",
        "model",
        "workspace_lane",
        "stable_lane",
        "lane_identity_sha256",
        "lane_path_identity_sha256",
        "workspace_owner_run_id",
        "source_manifest_sha256",
        "source_generation",
        "target_id",
        "target_generation",
    }
)


class ManagedContinuityContractError(ValueError):
    """Managed continuity policy or metadata is malformed."""


def canonical_sha256(value: object) -> str:
    payload = (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def validate_thread_continuity_policy(value: object) -> str:
    if type(value) is not str or value not in THREAD_CONTINUITY_POLICIES:
        raise ManagedContinuityContractError(
            "thread continuity policy must be fresh, captain_lane, or "
            "role_lane"
        )
    return value


def valid_thread_id(value: object) -> bool:
    return type(value) is str and _THREAD_ID.fullmatch(value) is not None


def thread_id_sha256(value: str) -> str:
    if not valid_thread_id(value):
        raise ManagedContinuityContractError(
            "provider thread identifier is not a bounded opaque token"
        )
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def source_generation(
    source_manifest_sha256: object,
    source_manifest_history: object,
) -> int:
    if (
        type(source_manifest_sha256) is not str
        or _SHA256.fullmatch(source_manifest_sha256) is None
    ):
        return 0
    if type(source_manifest_history) is not list:
        return 1
    return len(source_manifest_history) + 1


def build_session_metadata(
    *,
    policy: str,
    configuration_epoch: int,
    source_manifest_sha256: str | None,
    source_generation: int,
    target_id: str | None,
    target_generation: int | None,
    runtime_image_digest: str | None,
    captain_effort: str,
    worker_effort: str,
    models: Mapping[str, str],
) -> dict[str, Any]:
    policy = validate_thread_continuity_policy(policy)
    body: dict[str, Any] = {
        "schema_version": 1,
        "policy": policy,
        "configuration_epoch": configuration_epoch,
        "contract_version": THREAD_CONTINUITY_CONTRACT_VERSION,
        "source_manifest_sha256": source_manifest_sha256,
        "source_generation": source_generation,
        "target_id": target_id,
        "target_generation": target_generation,
        "runtime_image_digest": runtime_image_digest,
        "captain_effort": captain_effort,
        "worker_effort": worker_effort,
        "models": dict(sorted(models.items())),
    }
    body["configuration_fingerprint_sha256"] = canonical_sha256(body)
    return body


def session_metadata_errors(value: object) -> tuple[str, ...]:
    if type(value) is not dict:
        return ("metadata must be an exact object",)
    errors: list[str] = []
    if set(value) != _SESSION_KEYS:
        errors.append("metadata keys are not exact")
    if value.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    try:
        validate_thread_continuity_policy(value.get("policy"))
    except ManagedContinuityContractError:
        errors.append("policy is invalid")
    epoch = value.get("configuration_epoch")
    if type(epoch) is not int or epoch < 0:
        errors.append("configuration_epoch is invalid")
    if value.get("contract_version") != THREAD_CONTINUITY_CONTRACT_VERSION:
        errors.append("contract_version is invalid")
    manifest = value.get("source_manifest_sha256")
    if manifest is not None and (
        type(manifest) is not str or _SHA256.fullmatch(manifest) is None
    ):
        errors.append("source_manifest_sha256 is invalid")
    generation = value.get("source_generation")
    if type(generation) is not int or generation < 0:
        errors.append("source_generation is invalid")
    target_id = value.get("target_id")
    target_generation = value.get("target_generation")
    if (target_id is None) != (target_generation is None):
        errors.append("target id and generation must be jointly present")
    if target_id is not None and (
        type(target_id) is not str
        or not target_id
        or len(target_id.encode("utf-8")) > 256
        or type(target_generation) is not int
        or target_generation < 1
    ):
        errors.append("target binding is invalid")
    for key in (
        "captain_effort",
        "worker_effort",
    ):
        item = value.get(key)
        if type(item) is not str or not item or len(item) > 32:
            errors.append(f"{key} is invalid")
    digest = value.get("runtime_image_digest")
    if digest is not None and (
        type(digest) is not str or len(digest) > 128
    ):
        errors.append("runtime_image_digest is invalid")
    models = value.get("models")
    if (
        type(models) is not dict
        or not models
        or any(
            type(role) is not str
            or not role
            or type(model) is not str
            or not model
            or len(model) > 256
            for role, model in (
                models.items() if type(models) is dict else ()
            )
        )
    ):
        errors.append("models are invalid")
    fingerprint = value.get("configuration_fingerprint_sha256")
    if type(fingerprint) is not str or _SHA256.fullmatch(fingerprint) is None:
        errors.append("configuration fingerprint is invalid")
    elif set(value) == _SESSION_KEYS:
        unsigned = dict(value)
        unsigned.pop("configuration_fingerprint_sha256", None)
        if canonical_sha256(unsigned) != fingerprint:
            errors.append("configuration fingerprint does not match metadata")
    return tuple(errors)


def logical_workspace_lane(role: str) -> str:
    return f"managed-role-workspace-v1:{role}"


def build_lane_identity(
    *,
    session_id: str,
    configuration_fingerprint_sha256: str,
    configuration_epoch: int,
    role: str,
    model: str,
    source_manifest_sha256: str | None,
    source_generation: int,
    target_id: str | None,
    target_generation: int | None,
) -> str:
    return canonical_sha256(
        {
            "schema_version": 1,
            "session_id": session_id,
            "configuration_fingerprint_sha256": (
                configuration_fingerprint_sha256
            ),
            "configuration_epoch": configuration_epoch,
            "contract_version": THREAD_CONTINUITY_CONTRACT_VERSION,
            "logical_role": role,
            "model": model,
            "workspace_lane": logical_workspace_lane(role),
            "source_manifest_sha256": source_manifest_sha256,
            "source_generation": source_generation,
            "target_id": target_id,
            "target_generation": target_generation,
        }
    )


def lane_relative_path(lane_identity_sha256: str) -> str:
    if _SHA256.fullmatch(lane_identity_sha256) is None:
        raise ManagedContinuityContractError("lane identity is invalid")
    return (
        "runtime/managed-thread-lanes/"
        f"{lane_identity_sha256}/workspace"
    )


def lane_path_identity_sha256(lane_identity_sha256: str) -> str:
    return canonical_sha256(
        {
            "schema_version": 1,
            "relative_path": lane_relative_path(lane_identity_sha256),
        }
    )


def build_run_audit(
    *,
    session_metadata: Mapping[str, object],
    session_id: str,
    role: str,
    model: str,
    decision: str,
    reason: str,
    source_run_id: str | None,
    source_thread_id_sha256: str | None,
    stable_lane: bool,
    lane_identity_sha256: str | None,
    workspace_owner_run_id: str | None,
) -> dict[str, Any]:
    if session_metadata_errors(session_metadata):
        raise ManagedContinuityContractError(
            "cannot build an audit from invalid session metadata"
        )
    if reason not in THREAD_CONTINUITY_REASON_CODES:
        raise ManagedContinuityContractError("continuity reason is invalid")
    return {
        "schema_version": 1,
        "policy": session_metadata["policy"],
        "decision": decision,
        "reason": reason,
        "source_run_id": source_run_id,
        "thread_id_sha256": source_thread_id_sha256,
        "session_id": session_id,
        "configuration_epoch": session_metadata["configuration_epoch"],
        "configuration_fingerprint_sha256": session_metadata[
            "configuration_fingerprint_sha256"
        ],
        "contract_version": THREAD_CONTINUITY_CONTRACT_VERSION,
        "logical_role": role,
        "model": model,
        "workspace_lane": logical_workspace_lane(role),
        "stable_lane": stable_lane,
        "lane_identity_sha256": lane_identity_sha256,
        "lane_path_identity_sha256": (
            lane_path_identity_sha256(lane_identity_sha256)
            if lane_identity_sha256 is not None
            else None
        ),
        "workspace_owner_run_id": workspace_owner_run_id,
        "source_manifest_sha256": session_metadata[
            "source_manifest_sha256"
        ],
        "source_generation": session_metadata["source_generation"],
        "target_id": session_metadata["target_id"],
        "target_generation": session_metadata["target_generation"],
    }


def run_audit_errors(value: object) -> tuple[str, ...]:
    if type(value) is not dict:
        return ("audit must be an exact object",)
    errors: list[str] = []
    if set(value) != _AUDIT_KEYS:
        errors.append("audit keys are not exact")
    if "resume_thread_id" in value or "thread_id" in value:
        errors.append("audit contains a raw provider thread identifier")
    if value.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    try:
        policy = validate_thread_continuity_policy(value.get("policy"))
    except ManagedContinuityContractError:
        policy = ""
        errors.append("policy is invalid")
    decision = value.get("decision")
    if decision not in {"fresh", "resume"}:
        errors.append("decision is invalid")
    reason = value.get("reason")
    if reason not in THREAD_CONTINUITY_REASON_CODES:
        errors.append("reason is invalid")
    source_run_id = value.get("source_run_id")
    thread_hash = value.get("thread_id_sha256")
    if decision == "resume":
        if (
            type(source_run_id) is not str
            or not source_run_id
            or len(source_run_id.encode("utf-8")) > 256
        ):
            errors.append("resume source run is invalid")
        if type(thread_hash) is not str or _SHA256.fullmatch(thread_hash) is None:
            errors.append("resume thread hash is invalid")
        if reason != "resume_previous_completed_lane":
            errors.append("resume decision has an invalid reason")
    elif source_run_id is not None or thread_hash is not None:
        errors.append("fresh decision cannot retain a resume source")
    session_id = value.get("session_id")
    if (
        type(session_id) is not str
        or not session_id
        or len(session_id.encode("utf-8")) > 256
    ):
        errors.append("session_id is invalid")
    epoch = value.get("configuration_epoch")
    if type(epoch) is not int or epoch < 0:
        errors.append("configuration_epoch is invalid")
    if value.get("contract_version") != THREAD_CONTINUITY_CONTRACT_VERSION:
        errors.append("contract_version is invalid")
    for key in (
        "configuration_fingerprint_sha256",
        "lane_identity_sha256",
        "lane_path_identity_sha256",
    ):
        item = value.get(key)
        if key.startswith("lane_") and value.get("stable_lane") is False:
            if item is not None:
                errors.append(f"{key} must be null for an isolated run")
        elif type(item) is not str or _SHA256.fullmatch(item) is None:
            errors.append(f"{key} is invalid")
    for key in ("logical_role", "model", "workspace_lane"):
        item = value.get(key)
        if type(item) is not str or not item or len(item) > 256:
            errors.append(f"{key} is invalid")
    if (
        type(value.get("logical_role")) is str
        and value.get("workspace_lane")
        != logical_workspace_lane(value["logical_role"])
    ):
        errors.append("workspace lane does not match logical role")
    stable_lane = value.get("stable_lane")
    owner = value.get("workspace_owner_run_id")
    if type(stable_lane) is not bool:
        errors.append("stable_lane is invalid")
    elif stable_lane:
        if type(owner) is not str or not owner or len(owner) > 256:
            errors.append("stable lane owner is invalid")
    elif owner is not None:
        errors.append("isolated run cannot retain a lane owner")
    if policy == "fresh" and (
        decision != "fresh"
        or reason
        not in {"policy_fresh", "proof_wave_forced_fresh"}
        or stable_lane is not False
    ):
        errors.append("fresh policy cannot use a persistent lane")
    manifest = value.get("source_manifest_sha256")
    if manifest is not None and (
        type(manifest) is not str or _SHA256.fullmatch(manifest) is None
    ):
        errors.append("source manifest is invalid")
    generation = value.get("source_generation")
    if type(generation) is not int or generation < 0:
        errors.append("source generation is invalid")
    target_id = value.get("target_id")
    target_generation = value.get("target_generation")
    if (target_id is None) != (target_generation is None):
        errors.append("target binding is incomplete")
    if target_id is not None and (
        type(target_id) is not str
        or not target_id
        or len(target_id.encode("utf-8")) > 256
        or type(target_generation) is not int
        or target_generation < 1
    ):
        errors.append("target binding is invalid")
    lane_id = value.get("lane_identity_sha256")
    path_hash = value.get("lane_path_identity_sha256")
    if (
        stable_lane is True
        and type(lane_id) is str
        and _SHA256.fullmatch(lane_id) is not None
        and path_hash != lane_path_identity_sha256(lane_id)
    ):
        errors.append("lane path identity hash does not match lane identity")
    return tuple(errors)


__all__ = [
    "ManagedContinuityContractError",
    "THREAD_CONTINUITY_ALWAYS_FRESH_ROLES",
    "THREAD_CONTINUITY_CONTRACT_VERSION",
    "THREAD_CONTINUITY_ELIGIBLE_ROLES",
    "THREAD_CONTINUITY_POLICIES",
    "THREAD_CONTINUITY_REASON_CODES",
    "THREAD_CONTINUITY_RUN_KEY",
    "THREAD_CONTINUITY_SESSION_KEY",
    "build_lane_identity",
    "build_run_audit",
    "build_session_metadata",
    "canonical_sha256",
    "lane_path_identity_sha256",
    "lane_relative_path",
    "logical_workspace_lane",
    "run_audit_errors",
    "session_metadata_errors",
    "source_generation",
    "thread_id_sha256",
    "valid_thread_id",
    "validate_thread_continuity_policy",
]
