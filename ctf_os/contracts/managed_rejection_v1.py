"""Bounded engine-authored diagnostics for one rejected managed attempt.

The role-output validator currently reports human-readable errors.  Those
messages are useful in a run-local ``validation.json`` file, but they are not
safe to copy into a later model context: some messages can contain
model-controlled identifiers and future validators may include other
model-controlled values.

This contract projects those errors into a deliberately small vocabulary.
Only field names from the role-output schema and bounded numeric array
indices may survive as JSON pointers.  Messages, values, artifact paths, and
provider text never survive.  Artifact publication failures are identified
only by their one-based proposal ordinal and a closed engine code.

The module is standard-library-only and state-schema agnostic.  Callers may
store the returned JSON object in an existing engine-owned ``extra`` mapping.
Once persisted, v1 is append-only; semantic changes require a new version.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any


MANAGED_REJECTION_V1_SCHEMA_VERSION = 1
MANAGED_REJECTION_V1_AUTHORITY = "ctfos_engine"
MANAGED_REJECTION_V1_MAX_ATTEMPT = 64
MANAGED_REJECTION_V1_MAX_ISSUES = 16
MANAGED_REJECTION_V1_MAX_SOURCE_ISSUES = 256
MANAGED_REJECTION_V1_MAX_OMITTED = 65_535
MANAGED_REJECTION_V1_MAX_POINTER_BYTES = 256
MANAGED_REJECTION_V1_MAX_POINTER_SEGMENTS = 16
MANAGED_REJECTION_V1_MAX_ARRAY_INDEX = 65_535
MANAGED_REJECTION_V1_MAX_ARTIFACT_PROPOSALS = 8
MANAGED_REJECTION_V1_MAX_REPORTED_ARTIFACTS = 256
MANAGED_REJECTION_V1_MAX_SOURCE_ERROR_BYTES = 4096
MANAGED_REJECTION_V1_MAX_DOCUMENT_BYTES = 4096

MANAGED_REJECTION_V1_ROLES = frozenset(
    {
        "builder",
        "captain",
        "evidence_auditor",
        "extractor",
        "falsifier",
        "librarian",
        "recon",
        "reproducer",
        "specialist",
        "validator",
    }
)

MANAGED_REJECTION_V1_CONTRACT_CODES = frozenset(
    {
        "contract_invalid",
        "field_conflict",
        "field_forbidden",
        "invalid_identifier",
        "invalid_json",
        "invalid_value",
        "required_field_missing",
        "required_text_missing",
        "type_mismatch",
        "unexpected_field",
        "unsafe_relative_path",
    }
)

MANAGED_REJECTION_V1_ARTIFACT_CODES = frozenset(
    {
        "artifact_destination_conflict",
        "artifact_hash_mismatch",
        "artifact_publication_rejected",
        "artifact_size_limit_exceeded",
        "artifact_source_changed",
        "artifact_source_missing",
        "artifact_source_unopenable",
        "artifact_source_unsafe",
    }
)
MANAGED_REJECTION_V1_NORMALIZATION_CODES = frozenset(
    {
        "artifact_normalization_invalid",
        "reported_artifact_unavailable",
    }
)

# Pointer field names are closed so a caller cannot smuggle model-controlled
# text into a later prompt by presenting it as a JSONPath segment.
MANAGED_REJECTION_V1_POINTER_FIELDS = frozenset(
    {
        "action",
        "actions",
        "activate",
        "artifact_id",
        "artifact_ids",
        "artifact_path",
        "artifacts",
        "blocked_reason",
        "candidate_id",
        "claim",
        "command",
        "confidence",
        "decision",
        "depends_on",
        "description",
        "drop_if",
        "evaluations",
        "evidence",
        "evidence_artifact_ids",
        "evidence_fact_ids",
        "evidence_run_ids",
        "expected_observation",
        "experiment",
        "experiment_id",
        "falsifier",
        "flag_candidates",
        "goal_id",
        "goal_update",
        "hypotheses",
        "hypothesis_id",
        "hypothesis_ids",
        "hypothesis_updates",
        "id",
        "inputs",
        "keep_if",
        "kind",
        "message",
        "name",
        "network_target_generation",
        "network_target_id",
        "next_stage",
        "observations",
        "observation_refs",
        "path",
        "payload_artifact_path",
        "progress_markers",
        "provenance",
        "purpose",
        "reason",
        "refusal",
        "refute_hypothesis_ids",
        "refuted_by",
        "resource_class",
        "retryable",
        "role",
        "schema_version",
        "sha256",
        "source",
        "statement",
        "status",
        "success_oracle",
        "summary",
        "support_hypothesis_ids",
        "timeout_seconds",
        "unknowns",
        "value",
    }
)

_TOP_LEVEL_KEYS = frozenset(
    {
        "attempt",
        "authority",
        "issues",
        "omitted_count",
        "role",
        "schema_version",
    }
)
_CONTRACT_ISSUE_KEYS = frozenset({"code", "kind", "pointer"})
_ARTIFACT_ISSUE_KEYS = frozenset(
    {"code", "kind", "proposal_ordinal"}
)
_REPORTED_ARTIFACT_ISSUE_KEYS = frozenset(
    {"code", "kind", "pointer"}
)
_JSON_PATH_TOKEN = re.compile(
    r"\.([A-Za-z_][A-Za-z0-9_]{0,63})|\[(0|[1-9][0-9]{0,4})\]"
)


class ManagedRejectionV1ContractError(ValueError):
    """Raised when a diagnostic cannot be represented safely by v1."""


def managed_rejection_v1_canonical_json_bytes(value: object) -> bytes:
    """Return the bounded canonical JSON representation used by v1."""

    try:
        encoded = (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as error:
        raise ManagedRejectionV1ContractError(
            "managed rejection diagnostic is not canonical JSON"
        ) from error
    if len(encoded) > MANAGED_REJECTION_V1_MAX_DOCUMENT_BYTES:
        raise ManagedRejectionV1ContractError(
            "managed rejection diagnostic exceeds the byte limit"
        )
    return encoded


def _validate_role_attempt(role: object, attempt: object) -> tuple[str, int]:
    if type(role) is not str or role not in MANAGED_REJECTION_V1_ROLES:
        raise ManagedRejectionV1ContractError(
            "managed rejection role is not supported"
        )
    if (
        type(attempt) is not int
        or not 1 <= attempt <= MANAGED_REJECTION_V1_MAX_ATTEMPT
    ):
        raise ManagedRejectionV1ContractError(
            "managed rejection attempt is out of range"
        )
    return role, attempt


def _json_path_to_pointer(path: str) -> str | None:
    if path == "$":
        return ""
    if not path.startswith("$"):
        return None
    offset = 1
    segments: list[str] = []
    while offset < len(path):
        match = _JSON_PATH_TOKEN.match(path, offset)
        if match is None:
            return None
        field, raw_index = match.groups()
        if field is not None:
            if field not in MANAGED_REJECTION_V1_POINTER_FIELDS:
                return None
            segments.append(field)
        else:
            index = int(raw_index)
            if index > MANAGED_REJECTION_V1_MAX_ARRAY_INDEX:
                return None
            segments.append(raw_index)
        if len(segments) > MANAGED_REJECTION_V1_MAX_POINTER_SEGMENTS:
            return None
        offset = match.end()
    pointer = "".join(f"/{segment}" for segment in segments)
    if len(pointer.encode("ascii")) > MANAGED_REJECTION_V1_MAX_POINTER_BYTES:
        return None
    return pointer


def _validate_pointer(pointer: object) -> str:
    if type(pointer) is not str:
        raise ManagedRejectionV1ContractError(
            "managed rejection pointer must be a string"
        )
    if pointer == "":
        return pointer
    try:
        pointer_size = len(pointer.encode("utf-8", errors="strict"))
    except UnicodeError as error:
        raise ManagedRejectionV1ContractError(
            "managed rejection pointer is not valid UTF-8"
        ) from error
    if (
        not pointer.startswith("/")
        or pointer_size > MANAGED_REJECTION_V1_MAX_POINTER_BYTES
    ):
        raise ManagedRejectionV1ContractError(
            "managed rejection pointer is not bounded"
        )
    segments = pointer[1:].split("/")
    if (
        not segments
        or len(segments) > MANAGED_REJECTION_V1_MAX_POINTER_SEGMENTS
    ):
        raise ManagedRejectionV1ContractError(
            "managed rejection pointer has invalid depth"
        )
    for segment in segments:
        if segment in MANAGED_REJECTION_V1_POINTER_FIELDS:
            continue
        if (
            re.fullmatch(r"0|[1-9][0-9]{0,4}", segment)
            and int(segment) <= MANAGED_REJECTION_V1_MAX_ARRAY_INDEX
        ):
            continue
        raise ManagedRejectionV1ContractError(
            "managed rejection pointer contains an unapproved segment"
        )
    return pointer


def _contract_code(message: str) -> str:
    """Classify a validator message without returning any of its text."""

    if message.startswith("invalid JSON:"):
        return "invalid_json"
    if message.startswith("missing keys "):
        return "required_field_missing"
    if message.startswith("unexpected keys "):
        return "unexpected_field"
    if message in {
        "command action requires text",
        "create requires a description",
        "block requires a reason",
        "expected non-empty string",
        "expected non-empty string array",
    }:
        return "required_text_missing"
    if "expected safe relative path" in message:
        return "unsafe_relative_path"
    if (
        message.startswith("duplicate id")
        or message == "invalid id"
        or message == "invalid or duplicate id"
        or message == "invalid id or null"
    ):
        return "invalid_identifier"
    if (
        " is read-only" in message
        or " is restricted to " in message
        or " may not " in message
        or message.startswith("only ")
        or message.startswith("valid only for ")
    ):
        return "field_forbidden"
    if (
        " cannot " in message
        or " must be provided together" in message
        or "requires null" in message
        or "support/refute sets overlap" in message
    ):
        return "field_conflict"
    if message.startswith("expected "):
        return "type_mismatch"
    if message.startswith("invalid "):
        return "invalid_value"
    return "contract_invalid"


def _project_contract_error(error: str) -> dict[str, object]:
    try:
        raw_size = len(error.encode("utf-8", errors="strict"))
    except UnicodeError:
        return {
            "code": "contract_invalid",
            "kind": "role_output",
            "pointer": "",
        }
    if raw_size > MANAGED_REJECTION_V1_MAX_SOURCE_ERROR_BYTES:
        return {
            "code": "contract_invalid",
            "kind": "role_output",
            "pointer": "",
        }
    path, separator, message = error.partition(": ")
    pointer = _json_path_to_pointer(path) if separator else None
    if pointer is None:
        return {
            "code": "contract_invalid",
            "kind": "role_output",
            "pointer": "",
        }
    return {
        "code": _contract_code(message),
        "kind": "role_output",
        "pointer": pointer,
    }


def managed_artifact_publication_rejection_v1(
    *,
    proposal_ordinal: object,
    code: object,
) -> dict[str, object]:
    """Build one path-free artifact publication rejection issue."""

    if (
        type(proposal_ordinal) is not int
        or not 1
        <= proposal_ordinal
        <= MANAGED_REJECTION_V1_MAX_ARTIFACT_PROPOSALS
    ):
        raise ManagedRejectionV1ContractError(
            "artifact proposal ordinal is out of range"
        )
    if (
        type(code) is not str
        or code not in MANAGED_REJECTION_V1_ARTIFACT_CODES
    ):
        raise ManagedRejectionV1ContractError(
            "artifact publication rejection code is not supported"
        )
    return {
        "code": code,
        "kind": "artifact_publication",
        "proposal_ordinal": proposal_ordinal,
    }


def project_reported_artifact_normalization_error_v1(
    *,
    normalization_error: object,
    artifact_ordinal: object,
) -> dict[str, object]:
    """Project one run-wave artifact error without retaining its path/text.

    ``artifact_ordinal`` is zero-based because it points into the model's
    reported ``artifacts`` array.  The caller obtains it while normalizing the
    array; this function never attempts to recover or retain a reported path.
    Unknown or malformed error strings become the generic closed code.
    """

    if (
        type(artifact_ordinal) is not int
        or not 0
        <= artifact_ordinal
        < MANAGED_REJECTION_V1_MAX_REPORTED_ARTIFACTS
    ):
        raise ManagedRejectionV1ContractError(
            "reported artifact ordinal is out of range"
        )
    code = "artifact_normalization_invalid"
    if type(normalization_error) is str:
        try:
            error_size = len(
                normalization_error.encode("utf-8", errors="strict")
            )
        except UnicodeError:
            error_size = MANAGED_REJECTION_V1_MAX_SOURCE_ERROR_BYTES + 1
        prefix = "cannot snapshot reported artifact "
        if (
            error_size <= MANAGED_REJECTION_V1_MAX_SOURCE_ERROR_BYTES
            and normalization_error.startswith(prefix)
            and ": " in normalization_error[len(prefix) :]
        ):
            code = "reported_artifact_unavailable"
    return {
        "code": code,
        "kind": "reported_artifact",
        "pointer": f"/artifacts/{artifact_ordinal}/path",
    }


def _issue_sort_key(issue: Mapping[str, object]) -> tuple[object, ...]:
    if issue["kind"] == "role_output":
        return (0, issue["pointer"], issue["code"])
    if issue["kind"] == "reported_artifact":
        return (1, issue["pointer"], issue["code"])
    return (2, issue["proposal_ordinal"], issue["code"])


def _issue_identity(issue: Mapping[str, object]) -> tuple[object, ...]:
    return _issue_sort_key(issue)


def build_managed_rejection_v1(
    *,
    role: object,
    attempt: object,
    contract_errors: object = (),
    reported_artifact_rejections: object = (),
    artifact_publication_rejections: object = (),
) -> dict[str, object]:
    """Build one deterministic, bounded, message-free diagnostic object."""

    safe_role, safe_attempt = _validate_role_attempt(role, attempt)
    if (
        not isinstance(contract_errors, Sequence)
        or isinstance(contract_errors, (str, bytes, bytearray))
    ):
        raise ManagedRejectionV1ContractError(
            "contract errors must be an array"
        )
    if (
        not isinstance(reported_artifact_rejections, Sequence)
        or isinstance(
            reported_artifact_rejections,
            (str, bytes, bytearray),
        )
    ):
        raise ManagedRejectionV1ContractError(
            "reported artifact rejections must be an array"
        )
    if (
        not isinstance(artifact_publication_rejections, Sequence)
        or isinstance(
            artifact_publication_rejections,
            (str, bytes, bytearray),
        )
    ):
        raise ManagedRejectionV1ContractError(
            "artifact publication rejections must be an array"
        )

    source_count = (
        len(contract_errors)
        + len(reported_artifact_rejections)
        + len(artifact_publication_rejections)
    )
    issues: list[dict[str, object]] = []
    for error in contract_errors[:MANAGED_REJECTION_V1_MAX_SOURCE_ISSUES]:
        if type(error) is not str:
            raise ManagedRejectionV1ContractError(
                "contract error record must be a string"
            )
        issues.append(_project_contract_error(error))

    reported_limit = max(
        0,
        MANAGED_REJECTION_V1_MAX_SOURCE_ISSUES
        - min(
            len(contract_errors),
            MANAGED_REJECTION_V1_MAX_SOURCE_ISSUES,
        ),
    )
    seen_reported_pointers: set[str] = set()
    for raw_issue in reported_artifact_rejections[:reported_limit]:
        if not isinstance(raw_issue, Mapping):
            raise ManagedRejectionV1ContractError(
                "reported artifact rejection must be an object"
            )
        if set(raw_issue) != _REPORTED_ARTIFACT_ISSUE_KEYS:
            raise ManagedRejectionV1ContractError(
                "reported artifact rejection has a non-canonical schema"
            )
        if raw_issue.get("kind") != "reported_artifact":
            raise ManagedRejectionV1ContractError(
                "reported artifact rejection has an invalid kind"
            )
        code = raw_issue.get("code")
        if (
            type(code) is not str
            or code not in MANAGED_REJECTION_V1_NORMALIZATION_CODES
        ):
            raise ManagedRejectionV1ContractError(
                "reported artifact rejection code is not supported"
            )
        pointer = _validate_pointer(raw_issue.get("pointer"))
        if (
            re.fullmatch(r"/artifacts/(0|[1-9][0-9]{0,2})/path", pointer)
            is None
            or int(pointer.split("/")[2])
            >= MANAGED_REJECTION_V1_MAX_REPORTED_ARTIFACTS
        ):
            raise ManagedRejectionV1ContractError(
                "reported artifact rejection pointer is invalid"
            )
        if pointer in seen_reported_pointers:
            raise ManagedRejectionV1ContractError(
                "reported artifact ordinal is duplicated"
            )
        seen_reported_pointers.add(pointer)
        issues.append(
            {
                "code": code,
                "kind": "reported_artifact",
                "pointer": pointer,
            }
        )

    artifact_limit = max(
        0,
        reported_limit - min(
            len(reported_artifact_rejections),
            reported_limit,
        ),
    )
    seen_ordinals: set[int] = set()
    for raw_issue in artifact_publication_rejections[:artifact_limit]:
        if not isinstance(raw_issue, Mapping):
            raise ManagedRejectionV1ContractError(
                "artifact publication rejection must be an object"
            )
        if set(raw_issue) != {"code", "kind", "proposal_ordinal"}:
            raise ManagedRejectionV1ContractError(
                "artifact publication rejection has a non-canonical schema"
            )
        if raw_issue.get("kind") != "artifact_publication":
            raise ManagedRejectionV1ContractError(
                "artifact publication rejection has an invalid kind"
            )
        issue = managed_artifact_publication_rejection_v1(
            proposal_ordinal=raw_issue.get("proposal_ordinal"),
            code=raw_issue.get("code"),
        )
        ordinal = int(issue["proposal_ordinal"])
        if ordinal in seen_ordinals:
            raise ManagedRejectionV1ContractError(
                "artifact proposal ordinal is duplicated"
            )
        seen_ordinals.add(ordinal)
        issues.append(issue)

    unique: dict[tuple[object, ...], dict[str, object]] = {}
    for issue in issues:
        unique.setdefault(_issue_identity(issue), issue)
    ordered = sorted(unique.values(), key=_issue_sort_key)
    selected = ordered[:MANAGED_REJECTION_V1_MAX_ISSUES]
    omitted_count = min(
        MANAGED_REJECTION_V1_MAX_OMITTED,
        max(0, source_count - len(selected)),
    )
    if not selected:
        raise ManagedRejectionV1ContractError(
            "managed rejection diagnostic requires at least one issue"
        )

    document: dict[str, object] = {
        "attempt": safe_attempt,
        "authority": MANAGED_REJECTION_V1_AUTHORITY,
        "issues": selected,
        "omitted_count": omitted_count,
        "role": safe_role,
        "schema_version": MANAGED_REJECTION_V1_SCHEMA_VERSION,
    }
    return validate_managed_rejection_v1_mapping(document)


def validate_managed_rejection_v1_mapping(
    value: object,
) -> dict[str, object]:
    """Validate and return a fresh canonical v1 JSON mapping."""

    if not isinstance(value, Mapping) or set(value) != _TOP_LEVEL_KEYS:
        raise ManagedRejectionV1ContractError(
            "managed rejection diagnostic has a non-canonical schema"
        )
    role, attempt = _validate_role_attempt(
        value.get("role"),
        value.get("attempt"),
    )
    if (
        type(value.get("schema_version")) is not int
        or value.get("schema_version")
        != MANAGED_REJECTION_V1_SCHEMA_VERSION
        or value.get("authority") != MANAGED_REJECTION_V1_AUTHORITY
    ):
        raise ManagedRejectionV1ContractError(
            "managed rejection diagnostic identity is invalid"
        )
    omitted_count = value.get("omitted_count")
    if (
        type(omitted_count) is not int
        or not 0 <= omitted_count <= MANAGED_REJECTION_V1_MAX_OMITTED
    ):
        raise ManagedRejectionV1ContractError(
            "managed rejection omitted count is invalid"
        )
    raw_issues = value.get("issues")
    if (
        type(raw_issues) is not list
        or not 1 <= len(raw_issues) <= MANAGED_REJECTION_V1_MAX_ISSUES
    ):
        raise ManagedRejectionV1ContractError(
            "managed rejection issues are not a bounded array"
        )

    issues: list[dict[str, object]] = []
    seen_artifact_ordinals: set[int] = set()
    seen_reported_pointers: set[str] = set()
    for raw_issue in raw_issues:
        if not isinstance(raw_issue, Mapping):
            raise ManagedRejectionV1ContractError(
                "managed rejection issue must be an object"
            )
        kind = raw_issue.get("kind")
        if kind == "role_output":
            if set(raw_issue) != _CONTRACT_ISSUE_KEYS:
                raise ManagedRejectionV1ContractError(
                    "role-output rejection has a non-canonical schema"
                )
            code = raw_issue.get("code")
            if (
                type(code) is not str
                or code not in MANAGED_REJECTION_V1_CONTRACT_CODES
            ):
                raise ManagedRejectionV1ContractError(
                    "role-output rejection code is not supported"
                )
            issue = {
                "code": code,
                "kind": "role_output",
                "pointer": _validate_pointer(raw_issue.get("pointer")),
            }
        elif kind == "reported_artifact":
            if set(raw_issue) != _REPORTED_ARTIFACT_ISSUE_KEYS:
                raise ManagedRejectionV1ContractError(
                    "reported artifact rejection has a non-canonical schema"
                )
            code = raw_issue.get("code")
            if (
                type(code) is not str
                or code not in MANAGED_REJECTION_V1_NORMALIZATION_CODES
            ):
                raise ManagedRejectionV1ContractError(
                    "reported artifact rejection code is not supported"
                )
            pointer = _validate_pointer(raw_issue.get("pointer"))
            if (
                re.fullmatch(
                    r"/artifacts/(0|[1-9][0-9]{0,2})/path",
                    pointer,
                )
                is None
                or int(pointer.split("/")[2])
                >= MANAGED_REJECTION_V1_MAX_REPORTED_ARTIFACTS
            ):
                raise ManagedRejectionV1ContractError(
                    "reported artifact rejection pointer is invalid"
                )
            if pointer in seen_reported_pointers:
                raise ManagedRejectionV1ContractError(
                    "reported artifact ordinal is duplicated"
                )
            seen_reported_pointers.add(pointer)
            issue = {
                "code": code,
                "kind": "reported_artifact",
                "pointer": pointer,
            }
        elif kind == "artifact_publication":
            if set(raw_issue) != _ARTIFACT_ISSUE_KEYS:
                raise ManagedRejectionV1ContractError(
                    "artifact rejection has a non-canonical schema"
                )
            issue = managed_artifact_publication_rejection_v1(
                proposal_ordinal=raw_issue.get("proposal_ordinal"),
                code=raw_issue.get("code"),
            )
            ordinal = int(issue["proposal_ordinal"])
            if ordinal in seen_artifact_ordinals:
                raise ManagedRejectionV1ContractError(
                    "artifact proposal ordinal is duplicated"
                )
            seen_artifact_ordinals.add(ordinal)
        else:
            raise ManagedRejectionV1ContractError(
                "managed rejection issue kind is not supported"
            )
        issues.append(issue)

    if (
        issues != sorted(issues, key=_issue_sort_key)
        or len({_issue_identity(issue) for issue in issues}) != len(issues)
    ):
        raise ManagedRejectionV1ContractError(
            "managed rejection issues are not canonical"
        )
    document: dict[str, object] = {
        "attempt": attempt,
        "authority": MANAGED_REJECTION_V1_AUTHORITY,
        "issues": issues,
        "omitted_count": omitted_count,
        "role": role,
        "schema_version": MANAGED_REJECTION_V1_SCHEMA_VERSION,
    }
    managed_rejection_v1_canonical_json_bytes(document)
    return document


__all__ = [
    "MANAGED_REJECTION_V1_ARTIFACT_CODES",
    "MANAGED_REJECTION_V1_AUTHORITY",
    "MANAGED_REJECTION_V1_CONTRACT_CODES",
    "MANAGED_REJECTION_V1_MAX_ARTIFACT_PROPOSALS",
    "MANAGED_REJECTION_V1_MAX_ATTEMPT",
    "MANAGED_REJECTION_V1_MAX_DOCUMENT_BYTES",
    "MANAGED_REJECTION_V1_MAX_ISSUES",
    "MANAGED_REJECTION_V1_NORMALIZATION_CODES",
    "MANAGED_REJECTION_V1_ROLES",
    "MANAGED_REJECTION_V1_SCHEMA_VERSION",
    "ManagedRejectionV1ContractError",
    "build_managed_rejection_v1",
    "managed_artifact_publication_rejection_v1",
    "managed_rejection_v1_canonical_json_bytes",
    "project_reported_artifact_normalization_error_v1",
    "validate_managed_rejection_v1_mapping",
]
