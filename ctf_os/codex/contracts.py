"""Role routing and strict, dependency-free Codex output contracts."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath
from typing import Any, Mapping

from ctf_os.candidates import candidate_value_is_valid


class ModelFamily(str, Enum):
    SOL = "sol"
    TERRA = "terra"
    LUNA = "luna"


class ReasoningEffort(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    XHIGH = "xhigh"
    MAX = "max"
    ULTRA = "ultra"


class Role(str, Enum):
    CAPTAIN = "captain"
    RECON = "recon"
    SPECIALIST = "specialist"
    BUILDER = "builder"
    FALSIFIER = "falsifier"
    EXTRACTOR = "extractor"
    REPRODUCER = "reproducer"
    LIBRARIAN = "librarian"
    VALIDATOR = "validator"
    EVIDENCE_AUDITOR = "evidence_auditor"


@dataclass(frozen=True)
class RoleSpec:
    role: Role
    model_family: ModelFamily
    effort: ReasoningEffort
    sandbox: str
    may_write_artifacts: bool
    purpose: str


ROLE_SPECS: Mapping[Role, RoleSpec] = {
    Role.CAPTAIN: RoleSpec(
        Role.CAPTAIN,
        ModelFamily.SOL,
        ReasoningEffort.ULTRA,
        "read-only",
        False,
        "Interpret state, select a path, and propose the next stage.",
    ),
    Role.RECON: RoleSpec(
        Role.RECON,
        ModelFamily.TERRA,
        ReasoningEffort.MAX,
        "read-only",
        False,
        "Map the attack surface and record direct observations.",
    ),
    Role.SPECIALIST: RoleSpec(
        Role.SPECIALIST,
        ModelFamily.TERRA,
        ReasoningEffort.MAX,
        "read-only",
        False,
        "Perform category-specific analysis and propose discriminating tests.",
    ),
    Role.BUILDER: RoleSpec(
        Role.BUILDER,
        ModelFamily.SOL,
        ReasoningEffort.MAX,
        "workspace-write",
        True,
        "Implement one solver or exploit as the sole analysis-workspace writer.",
    ),
    Role.FALSIFIER: RoleSpec(
        Role.FALSIFIER,
        ModelFamily.SOL,
        ReasoningEffort.MAX,
        "read-only",
        False,
        "Independently try to disprove hypotheses and candidate paths.",
    ),
    Role.EXTRACTOR: RoleSpec(
        Role.EXTRACTOR,
        ModelFamily.LUNA,
        ReasoningEffort.MAX,
        "read-only",
        False,
        "Structure large tool outputs without making path decisions.",
    ),
    Role.REPRODUCER: RoleSpec(
        Role.REPRODUCER,
        ModelFamily.TERRA,
        ReasoningEffort.MAX,
        "workspace-write",
        True,
        "Reproduce a candidate in a clean proof workspace.",
    ),
    Role.LIBRARIAN: RoleSpec(
        Role.LIBRARIAN,
        ModelFamily.TERRA,
        ReasoningEffort.MAX,
        "read-only",
        False,
        "Find relevant references while preserving source provenance.",
    ),
    Role.VALIDATOR: RoleSpec(
        Role.VALIDATOR,
        ModelFamily.SOL,
        ReasoningEffort.MAX,
        "read-only",
        False,
        "Validate candidate correctness and proof claims without modifying artifacts.",
    ),
    Role.EVIDENCE_AUDITOR: RoleSpec(
        Role.EVIDENCE_AUDITOR,
        ModelFamily.LUNA,
        ReasoningEffort.MAX,
        "read-only",
        False,
        "Audit evidence provenance and flag-source contamination without deciding the path.",
    ),
}


@dataclass(frozen=True)
class ModelCatalog:
    """Concrete CLI model ids for the three logical model families.

    The aliases are deliberately configurable because account-visible model ids
    can differ. The engine configuration should override these defaults when an
    account exposes different ids.
    """

    sol: str = "gpt-5.6-sol"
    terra: str = "gpt-5.6-terra"
    luna: str = "gpt-5.6-luna"

    def resolve(self, family: ModelFamily) -> str:
        model_id = {
            ModelFamily.SOL: self.sol,
            ModelFamily.TERRA: self.terra,
            ModelFamily.LUNA: self.luna,
        }[family]
        if not model_id or not model_id.strip():
            raise ValueError(f"no concrete model id configured for {family.value}")
        return model_id


PROVENANCE_VALUES = (
    "executed",
    "tool_inferred",
    "model_claimed",
    "external_doc",
    "operator",
)
FLAG_SOURCE_VALUES = ("derived", "tool_output", "file_read", "external", "unknown")
STATUS_VALUES = ("ok", "blocked", "needs_human", "refused")
NEXT_STAGE_VALUES = ("discover", "attack", "proof", "pause", "complete", "needs_human")
ACTION_KIND_VALUES = ("command", "write_artifact", "research", "human_request", "none")
GOAL_ACTION_VALUES = ("create", "activate", "complete", "block", "park")
HYPOTHESIS_STATUS_VALUES = ("open", "supported", "refuted", "confirmed")
EVALUATION_STATUS_VALUES = ("kept", "dropped", "inconclusive", "failed")
ACTION_RESOURCE_CLASS_VALUES = ("light", "standard", "heavy", "gpu")

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_REFERENCE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def role_output_schema(
    role: Role,
    *,
    contract_version: int = 1,
) -> dict[str, Any]:
    """Return the exact JSON Schema requested from a batch role."""

    if (
        isinstance(contract_version, bool)
        or contract_version not in {1, 2}
    ):
        raise ValueError("contract_version must be 1 or 2")
    nullable_string = {"type": ["string", "null"]}
    action_kinds = (
        ACTION_KIND_VALUES
        if ROLE_SPECS[role].may_write_artifacts
        else tuple(value for value in ACTION_KIND_VALUES if value != "write_artifact")
    )
    decision_schema: dict[str, Any]
    if role is Role.CAPTAIN:
        decision_schema = {
            "anyOf": [
                {"type": "null"},
                {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["next_stage", "reason"],
                    "properties": {
                        "next_stage": {"enum": list(NEXT_STAGE_VALUES)},
                        "reason": {"type": "string"},
                    },
                },
            ]
        }
    else:
        decision_schema = {"type": "null"}
    goal_update_schema: dict[str, Any]
    if role is Role.CAPTAIN:
        goal_update_schema = {
            "anyOf": [
                {"type": "null"},
                {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "action",
                        "goal_id",
                        "description",
                        "depends_on",
                        "artifact_ids",
                        "blocked_reason",
                        "activate",
                    ],
                    "properties": {
                        "action": {"enum": list(GOAL_ACTION_VALUES)},
                        "goal_id": {"type": "string"},
                        "description": nullable_string,
                        "depends_on": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "artifact_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "blocked_reason": nullable_string,
                        "activate": {"type": "boolean"},
                    },
                },
            ]
        }
    else:
        goal_update_schema = {"type": "null"}
    action_properties: dict[str, Any] = {
        "kind": {"enum": list(action_kinds)},
        "description": {"type": "string"},
        "command": nullable_string,
        "artifact_path": nullable_string,
    }
    action_required = [
        "kind",
        "description",
        "command",
        "artifact_path",
    ]
    if contract_version == 2:
        action_properties.update(
            {
                "hypothesis_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                "expected_observation": {"type": "string"},
                "keep_if": {"type": "string"},
                "drop_if": {"type": "string"},
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 28_800,
                },
                "resource_class": {
                    "enum": list(ACTION_RESOURCE_CLASS_VALUES)
                },
                "network_target_id": {
                    "type": ["string", "null"],
                    "minLength": 1,
                    "maxLength": 1024,
                    "pattern": r"^[^\u0000-\u0020\u007F]+$",
                },
                "network_target_generation": {
                    "type": ["integer", "null"],
                    "minimum": 1,
                },
            }
        )
        action_required.extend(
            (
                "hypothesis_ids",
                "expected_observation",
                "keep_if",
                "drop_if",
                "timeout_seconds",
                "resource_class",
                "network_target_id",
                "network_target_generation",
            )
        )
        action_variants: list[dict[str, Any]] = []
        for action_kind in action_kinds:
            variant_properties = dict(action_properties)
            variant_properties["kind"] = {"enum": [action_kind]}
            variant_properties["command"] = (
                {"type": "string", "minLength": 1}
                if action_kind == "command"
                else {"type": "null"}
            )
            variant_properties["artifact_path"] = (
                {"type": "string", "minLength": 1}
                if action_kind == "write_artifact"
                else {"type": "null"}
            )
            action_variants.append(
                {
                    "type": "object",
                    "additionalProperties": False,
                    "required": action_required,
                    "properties": variant_properties,
                }
            )
        action_items_schema: dict[str, Any] = {
            "anyOf": action_variants,
        }
    else:
        action_items_schema = {
            "type": "object",
            "additionalProperties": False,
            "required": action_required,
            "properties": action_properties,
        }
    if contract_version == 2:
        hypothesis_items_schema: dict[str, Any] = {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "id",
                "claim",
                "evidence",
                "unknowns",
                "experiment",
                "success_oracle",
                "falsifier",
            ],
            "properties": {
                "id": {"type": "string"},
                "claim": {"type": "string", "minLength": 1},
                "evidence": {
                    "type": "array",
                    "minItems": 1,
                    "items": {"type": "string", "minLength": 1},
                },
                "unknowns": {
                    "type": "array",
                    "minItems": 1,
                    "items": {"type": "string", "minLength": 1},
                },
                "experiment": {
                    "type": "string",
                    "minLength": 1,
                },
                "success_oracle": {
                    "type": "string",
                    "minLength": 1,
                },
                "falsifier": {"type": "string", "minLength": 1},
            },
        }
    else:
        hypothesis_items_schema = {
            "type": "object",
            "additionalProperties": False,
            "required": [
                "id",
                "statement",
                "observation_refs",
                "falsifier",
                "keep_if",
                "drop_if",
            ],
            "properties": {
                "id": {"type": "string"},
                "statement": {"type": "string"},
                "observation_refs": {
                    "type": "array",
                    "items": {"type": "string"},
                },
                "falsifier": {"type": "string"},
                "keep_if": {"type": "string"},
                "drop_if": {"type": "string"},
            },
        }
    return {
        "title": f"CTF-OS {role.value} result",
        "type": "object",
        "additionalProperties": False,
        "required": [
            "schema_version",
            "role",
            "status",
            "summary",
            "observations",
            "hypotheses",
            "hypothesis_updates",
            "evaluations",
            "actions",
            "artifacts",
            "progress_markers",
            "flag_candidates",
            "decision",
            "goal_update",
            "refusal",
        ],
        "properties": {
            "schema_version": {
                "type": "integer",
                "enum": [contract_version],
            },
            "role": {"type": "string", "enum": [role.value]},
            "status": {"enum": list(STATUS_VALUES)},
            "summary": {"type": "string"},
            "observations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["id", "claim", "evidence", "provenance"],
                    "properties": {
                        "id": {"type": "string"},
                        "claim": {"type": "string"},
                        "evidence": {"type": "array", "items": {"type": "string"}},
                        "provenance": {"enum": list(PROVENANCE_VALUES)},
                    },
                },
            },
            "hypotheses": {
                "type": "array",
                "items": hypothesis_items_schema,
            },
            "hypothesis_updates": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "hypothesis_id",
                        "statement",
                        "falsifier",
                        "status",
                        "evidence_fact_ids",
                        "evidence_artifact_ids",
                        "evidence_run_ids",
                        "confidence",
                        "refuted_by",
                    ],
                    "properties": {
                        "hypothesis_id": {"type": "string"},
                        "statement": nullable_string,
                        "falsifier": nullable_string,
                        "status": {
                            "enum": list(HYPOTHESIS_STATUS_VALUES)
                        },
                        "evidence_fact_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "evidence_artifact_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "evidence_run_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "confidence": {
                            "type": ["number", "null"],
                            "minimum": 0,
                            "maximum": 1,
                        },
                        "refuted_by": nullable_string,
                    },
                },
            },
            "evaluations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "experiment_id",
                        "status",
                        "reason",
                        "evidence_fact_ids",
                        "evidence_artifact_ids",
                        "evidence_run_ids",
                        "support_hypothesis_ids",
                        "refute_hypothesis_ids",
                    ],
                    "properties": {
                        "experiment_id": {"type": "string"},
                        "status": {
                            "enum": list(EVALUATION_STATUS_VALUES)
                        },
                        "reason": {"type": "string"},
                        "evidence_fact_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "evidence_artifact_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "evidence_run_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "support_hypothesis_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "refute_hypothesis_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                    },
                },
            },
            "actions": {
                "type": "array",
                "items": action_items_schema,
            },
            "artifacts": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["path", "sha256", "purpose"],
                    "properties": {
                        "path": {"type": "string"},
                        "sha256": {
                            "anyOf": [
                                {"type": "null"},
                                {"type": "string"},
                            ]
                        },
                        "purpose": {"type": "string"},
                    },
                },
            },
            "progress_markers": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["name", "evidence"],
                    "properties": {
                        "name": {"type": "string"},
                        "evidence": {"type": "string"},
                    },
                },
            },
            "flag_candidates": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["value", "source", "evidence"],
                    "properties": {
                        "value": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 1024,
                            "pattern": r"^[^\u0000-\u001F\u007F]+$",
                        },
                        "source": {"enum": list(FLAG_SOURCE_VALUES)},
                        "evidence": {"type": "string"},
                    },
                },
            },
            "decision": decision_schema,
            "goal_update": goal_update_schema,
            "refusal": {
                "anyOf": [
                    {"type": "null"},
                    {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["kind", "message", "retryable"],
                        "properties": {
                            "kind": {"type": "string"},
                            "message": {"type": "string"},
                            "retryable": {"type": "boolean"},
                        },
                    },
                ]
            },
        },
    }


@dataclass(frozen=True)
class ContractValidation:
    valid: bool
    errors: tuple[str, ...]
    value: Mapping[str, Any] | None


def _exact_keys(
    value: Mapping[str, Any], required: set[str], path: str, errors: list[str]
) -> None:
    missing = sorted(required - set(value))
    extra = sorted(set(value) - required)
    if missing:
        errors.append(f"{path}: missing keys {missing}")
    if extra:
        errors.append(f"{path}: unexpected keys {extra}")


def _is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _valid_relative_path(value: str) -> bool:
    path = PurePosixPath(value)
    return (
        bool(value)
        and value != "."
        and "\x00" not in value
        and "\\" not in value
        and len(value.encode("utf-8")) <= 4096
        and all(len(part.encode("utf-8")) <= 255 for part in path.parts)
        and not path.is_absolute()
        and ".." not in path.parts
    )


def validate_role_output(
    payload: str | bytes | Mapping[str, Any],
    role: Role,
    *,
    contract_version: int = 1,
) -> ContractValidation:
    """Strictly validate a role result without relying on a JSON Schema package."""

    if (
        isinstance(contract_version, bool)
        or contract_version not in {1, 2}
    ):
        raise ValueError("contract_version must be 1 or 2")
    errors: list[str] = []
    if isinstance(payload, (str, bytes)):
        try:
            value = json.loads(payload)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            return ContractValidation(False, (f"$: invalid JSON: {exc}",), None)
    else:
        value = payload

    if not isinstance(value, Mapping):
        return ContractValidation(False, ("$: expected object",), None)

    top_keys = {
        "schema_version",
        "role",
        "status",
        "summary",
        "observations",
        "hypotheses",
        "hypothesis_updates",
        "evaluations",
        "actions",
        "artifacts",
        "progress_markers",
        "flag_candidates",
        "decision",
        "goal_update",
        "refusal",
    }
    _exact_keys(value, top_keys, "$", errors)
    if (
        type(value.get("schema_version")) is not int
        or value.get("schema_version") != contract_version
    ):
        errors.append(
            f"$.schema_version: expected {contract_version}"
        )
    if value.get("role") != role.value:
        errors.append(f"$.role: expected {role.value!r}")
    if value.get("status") not in STATUS_VALUES:
        errors.append(f"$.status: expected one of {STATUS_VALUES}")
    if not isinstance(value.get("summary"), str):
        errors.append("$.summary: expected string")

    observations = value.get("observations")
    observation_ids: set[str] = set()
    if not isinstance(observations, list):
        errors.append("$.observations: expected array")
    else:
        keys = {"id", "claim", "evidence", "provenance"}
        for index, item in enumerate(observations):
            path = f"$.observations[{index}]"
            if not isinstance(item, Mapping):
                errors.append(f"{path}: expected object")
                continue
            _exact_keys(item, keys, path, errors)
            item_id = item.get("id")
            if not isinstance(item_id, str) or not _ID_RE.fullmatch(item_id):
                errors.append(f"{path}.id: invalid id")
            elif item_id in observation_ids:
                errors.append(f"{path}.id: duplicate id {item_id!r}")
            else:
                observation_ids.add(item_id)
            if not isinstance(item.get("claim"), str):
                errors.append(f"{path}.claim: expected string")
            if not _is_string_list(item.get("evidence")):
                errors.append(f"{path}.evidence: expected string array")
            if item.get("provenance") not in PROVENANCE_VALUES:
                errors.append(f"{path}.provenance: invalid provenance")

    hypotheses = value.get("hypotheses")
    hypothesis_ids: set[str] = set()
    if not isinstance(hypotheses, list):
        errors.append("$.hypotheses: expected array")
    else:
        keys = (
            {
                "id",
                "claim",
                "evidence",
                "unknowns",
                "experiment",
                "success_oracle",
                "falsifier",
            }
            if contract_version == 2
            else {
                "id",
                "statement",
                "observation_refs",
                "falsifier",
                "keep_if",
                "drop_if",
            }
        )
        for index, item in enumerate(hypotheses):
            path = f"$.hypotheses[{index}]"
            if not isinstance(item, Mapping):
                errors.append(f"{path}: expected object")
                continue
            _exact_keys(item, keys, path, errors)
            item_id = item.get("id")
            if not isinstance(item_id, str) or not _ID_RE.fullmatch(item_id):
                errors.append(f"{path}.id: invalid id")
            elif item_id in hypothesis_ids:
                errors.append(f"{path}.id: duplicate id {item_id!r}")
            else:
                hypothesis_ids.add(item_id)
            if contract_version == 2:
                for field in (
                    "claim",
                    "experiment",
                    "success_oracle",
                    "falsifier",
                ):
                    field_value = item.get(field)
                    if (
                        not isinstance(field_value, str)
                        or not field_value.strip()
                    ):
                        errors.append(
                            f"{path}.{field}: expected non-empty string"
                        )
                for field in ("evidence", "unknowns"):
                    values = item.get(field)
                    if (
                        not _is_string_list(values)
                        or not values
                        or any(not value.strip() for value in values)
                    ):
                        errors.append(
                            f"{path}.{field}: expected non-empty string array"
                        )
            else:
                for field in (
                    "statement",
                    "falsifier",
                    "keep_if",
                    "drop_if",
                ):
                    if not isinstance(item.get(field), str):
                        errors.append(f"{path}.{field}: expected string")
                refs = item.get("observation_refs")
                if not _is_string_list(refs):
                    errors.append(
                        f"{path}.observation_refs: expected string array"
                    )
            # A proposal may reference observations already present in state,
            # which this state-independent validator cannot resolve.

    hypothesis_updates = value.get("hypothesis_updates")
    if not isinstance(hypothesis_updates, list):
        errors.append("$.hypothesis_updates: expected array")
    else:
        keys = {
            "hypothesis_id",
            "statement",
            "falsifier",
            "status",
            "evidence_fact_ids",
            "evidence_artifact_ids",
            "evidence_run_ids",
            "confidence",
            "refuted_by",
        }
        for index, item in enumerate(hypothesis_updates):
            path = f"$.hypothesis_updates[{index}]"
            if not isinstance(item, Mapping):
                errors.append(f"{path}: expected object")
                continue
            _exact_keys(item, keys, path, errors)
            hypothesis_id = item.get("hypothesis_id")
            if (
                not isinstance(hypothesis_id, str)
                or not _REFERENCE_ID_RE.fullmatch(hypothesis_id)
            ):
                errors.append(f"{path}.hypothesis_id: invalid id")
            for field in ("statement", "falsifier", "refuted_by"):
                if item.get(field) is not None and not isinstance(
                    item.get(field), str
                ):
                    errors.append(f"{path}.{field}: expected string or null")
            status = item.get("status")
            if status not in HYPOTHESIS_STATUS_VALUES:
                errors.append(f"{path}.status: invalid hypothesis status")
            for field in (
                "evidence_fact_ids",
                "evidence_artifact_ids",
                "evidence_run_ids",
            ):
                if not _is_string_list(item.get(field)):
                    errors.append(f"{path}.{field}: expected string array")
            confidence = item.get("confidence")
            if confidence is not None and (
                isinstance(confidence, bool)
                or not isinstance(confidence, (int, float))
                or not 0 <= confidence <= 1
            ):
                errors.append(
                    f"{path}.confidence: expected number from 0 to 1 or null"
                )
            if status != "refuted" and item.get("refuted_by") is not None:
                errors.append(
                    f"{path}.refuted_by: valid only for refuted status"
                )

    evaluations = value.get("evaluations")
    if not isinstance(evaluations, list):
        errors.append("$.evaluations: expected array")
    else:
        keys = {
            "experiment_id",
            "status",
            "reason",
            "evidence_fact_ids",
            "evidence_artifact_ids",
            "evidence_run_ids",
            "support_hypothesis_ids",
            "refute_hypothesis_ids",
        }
        for index, item in enumerate(evaluations):
            path = f"$.evaluations[{index}]"
            if not isinstance(item, Mapping):
                errors.append(f"{path}: expected object")
                continue
            _exact_keys(item, keys, path, errors)
            experiment_id = item.get("experiment_id")
            if not isinstance(experiment_id, str) or not _REFERENCE_ID_RE.fullmatch(
                experiment_id
            ):
                errors.append(f"{path}.experiment_id: invalid id")
            status = item.get("status")
            if status not in EVALUATION_STATUS_VALUES:
                errors.append(f"{path}.status: invalid evaluation status")
            if not isinstance(item.get("reason"), str):
                errors.append(f"{path}.reason: expected string")
            for field in (
                "evidence_fact_ids",
                "evidence_artifact_ids",
                "evidence_run_ids",
                "support_hypothesis_ids",
                "refute_hypothesis_ids",
            ):
                if not _is_string_list(item.get(field)):
                    errors.append(f"{path}.{field}: expected string array")
            support_ids = item.get("support_hypothesis_ids")
            refute_ids = item.get("refute_hypothesis_ids")
            if isinstance(support_ids, list) and isinstance(refute_ids, list):
                overlap = set(support_ids) & set(refute_ids)
                if overlap:
                    errors.append(
                        f"{path}: support/refute sets overlap: "
                        f"{sorted(overlap)}"
                    )
                if status in {"inconclusive", "failed"} and (
                    support_ids or refute_ids
                ):
                    errors.append(
                        f"{path}: {status} cannot change hypotheses"
                    )
                if status == "kept" and refute_ids:
                    errors.append(
                        f"{path}: kept cannot refute hypotheses"
                    )
                if status == "dropped" and support_ids:
                    errors.append(
                        f"{path}: dropped cannot support hypotheses"
                    )

    actions = value.get("actions")
    if not isinstance(actions, list):
        errors.append("$.actions: expected array")
    else:
        keys = {
            "kind",
            "description",
            "command",
            "artifact_path",
        }
        if contract_version == 2:
            keys.update(
                {
                    "hypothesis_ids",
                    "expected_observation",
                    "keep_if",
                    "drop_if",
                    "timeout_seconds",
                    "resource_class",
                    "network_target_id",
                    "network_target_generation",
                }
            )
        for index, item in enumerate(actions):
            path = f"$.actions[{index}]"
            if not isinstance(item, Mapping):
                errors.append(f"{path}: expected object")
                continue
            _exact_keys(item, keys, path, errors)
            kind = item.get("kind")
            if kind not in ACTION_KIND_VALUES:
                errors.append(f"{path}.kind: invalid kind")
            if not isinstance(item.get("description"), str):
                errors.append(f"{path}.description: expected string")
            for field in ("command", "artifact_path"):
                if item.get(field) is not None and not isinstance(item.get(field), str):
                    errors.append(f"{path}.{field}: expected string or null")
            artifact_path = item.get("artifact_path")
            if isinstance(artifact_path, str) and not _valid_relative_path(artifact_path):
                errors.append(f"{path}.artifact_path: expected safe relative path")
            if kind == "write_artifact" and not ROLE_SPECS[role].may_write_artifacts:
                errors.append(f"{path}.kind: {role.value} is read-only")
            if contract_version == 2:
                action_hypothesis_ids = item.get("hypothesis_ids")
                if not _is_string_list(action_hypothesis_ids):
                    errors.append(
                        f"{path}.hypothesis_ids: expected string array"
                    )
                elif (
                    any(
                        not _REFERENCE_ID_RE.fullmatch(item_id)
                        for item_id in action_hypothesis_ids
                    )
                    or len(set(action_hypothesis_ids))
                    != len(action_hypothesis_ids)
                ):
                    errors.append(
                        f"{path}.hypothesis_ids: invalid or duplicate id"
                    )
                for field in (
                    "expected_observation",
                    "keep_if",
                    "drop_if",
                ):
                    field_value = item.get(field)
                    if not isinstance(field_value, str):
                        errors.append(
                            f"{path}.{field}: expected string"
                        )
                    elif kind == "command" and not field_value.strip():
                        errors.append(
                            f"{path}.{field}: command action requires text"
                        )
                timeout_seconds = item.get("timeout_seconds")
                if (
                    isinstance(timeout_seconds, bool)
                    or not isinstance(timeout_seconds, int)
                    or not 1 <= timeout_seconds <= 28_800
                ):
                    errors.append(
                        f"{path}.timeout_seconds: expected integer "
                        "from 1 to 28800"
                    )
                if (
                    item.get("resource_class")
                    not in ACTION_RESOURCE_CLASS_VALUES
                ):
                    errors.append(
                        f"{path}.resource_class: invalid resource class"
                    )
                target_id = item.get("network_target_id")
                target_generation = item.get(
                    "network_target_generation"
                )
                if target_id is not None and (
                    not isinstance(target_id, str)
                    or not candidate_value_is_valid(target_id)
                    or any(character.isspace() for character in target_id)
                ):
                    errors.append(
                        f"{path}.network_target_id: invalid id or null"
                    )
                if target_generation is not None and (
                    isinstance(target_generation, bool)
                    or not isinstance(target_generation, int)
                    or target_generation < 1
                ):
                    errors.append(
                        f"{path}.network_target_generation: expected "
                        "positive integer or null"
                    )
                if (target_id is None) != (
                    target_generation is None
                ):
                    errors.append(
                        f"{path}: target id and generation must be "
                        "provided together"
                    )
                if kind == "command":
                    if (
                        not isinstance(item.get("command"), str)
                        or not str(item["command"]).strip()
                    ):
                        errors.append(
                            f"{path}.command: command action requires text"
                        )
                    if item.get("artifact_path") is not None:
                        errors.append(
                            f"{path}.artifact_path: command action "
                            "requires null"
                        )
                elif target_id is not None:
                    errors.append(
                        f"{path}.network_target_id: only command actions "
                        "may request a target"
                    )

    artifacts = value.get("artifacts")
    if not isinstance(artifacts, list):
        errors.append("$.artifacts: expected array")
    else:
        keys = {"path", "sha256", "purpose"}
        for index, item in enumerate(artifacts):
            path = f"$.artifacts[{index}]"
            if not isinstance(item, Mapping):
                errors.append(f"{path}: expected object")
                continue
            _exact_keys(item, keys, path, errors)
            artifact_path = item.get("path")
            if not isinstance(artifact_path, str) or not _valid_relative_path(artifact_path):
                errors.append(f"{path}.path: expected safe relative path")
            digest = item.get("sha256")
            if digest is not None and (
                not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest)
            ):
                errors.append(f"{path}.sha256: expected lowercase SHA-256 or null")
            if not isinstance(item.get("purpose"), str):
                errors.append(f"{path}.purpose: expected string")

    progress_markers = value.get("progress_markers")
    if not isinstance(progress_markers, list):
        errors.append("$.progress_markers: expected array")
    else:
        keys = {"name", "evidence"}
        for index, item in enumerate(progress_markers):
            path = f"$.progress_markers[{index}]"
            if not isinstance(item, Mapping):
                errors.append(f"{path}: expected object")
                continue
            _exact_keys(item, keys, path, errors)
            for field in keys:
                if not isinstance(item.get(field), str):
                    errors.append(f"{path}.{field}: expected string")

    flag_candidates = value.get("flag_candidates")
    if not isinstance(flag_candidates, list):
        errors.append("$.flag_candidates: expected array")
    else:
        keys = {"value", "source", "evidence"}
        for index, item in enumerate(flag_candidates):
            path = f"$.flag_candidates[{index}]"
            if not isinstance(item, Mapping):
                errors.append(f"{path}: expected object")
                continue
            _exact_keys(item, keys, path, errors)
            candidate = item.get("value")
            if not candidate_value_is_valid(candidate):
                errors.append(
                    f"{path}.value: expected 1..1024 printable characters "
                    "and at most 4096 UTF-8 bytes"
                )
            if item.get("source") not in FLAG_SOURCE_VALUES:
                errors.append(f"{path}.source: invalid source")
            if not isinstance(item.get("evidence"), str):
                errors.append(f"{path}.evidence: expected string")

    decision = value.get("decision")
    if decision is not None:
        path = "$.decision"
        if not isinstance(decision, Mapping):
            errors.append(f"{path}: expected object or null")
        else:
            _exact_keys(decision, {"next_stage", "reason"}, path, errors)
            if decision.get("next_stage") not in NEXT_STAGE_VALUES:
                errors.append(f"{path}.next_stage: invalid stage")
            if not isinstance(decision.get("reason"), str):
                errors.append(f"{path}.reason: expected string")
    if role is Role.CAPTAIN and value.get("status") == "ok" and decision is None:
        errors.append("$.decision: captain with ok status must choose a next stage")
    if role is not Role.CAPTAIN and decision is not None:
        errors.append(f"$.decision: {role.value} may not make engine decisions")

    goal_update = value.get("goal_update")
    if goal_update is not None:
        path = "$.goal_update"
        if not isinstance(goal_update, Mapping):
            errors.append(f"{path}: expected object or null")
        else:
            keys = {
                "action",
                "goal_id",
                "description",
                "depends_on",
                "artifact_ids",
                "blocked_reason",
                "activate",
            }
            _exact_keys(goal_update, keys, path, errors)
            action = goal_update.get("action")
            if action not in GOAL_ACTION_VALUES:
                errors.append(f"{path}.action: invalid goal action")
            goal_id = goal_update.get("goal_id")
            if not isinstance(goal_id, str) or not _REFERENCE_ID_RE.fullmatch(goal_id):
                errors.append(f"{path}.goal_id: invalid id")
            for field in ("description", "blocked_reason"):
                if goal_update.get(field) is not None and not isinstance(
                    goal_update.get(field), str
                ):
                    errors.append(f"{path}.{field}: expected string or null")
            for field in ("depends_on", "artifact_ids"):
                if not _is_string_list(goal_update.get(field)):
                    errors.append(f"{path}.{field}: expected string array")
            if not isinstance(goal_update.get("activate"), bool):
                errors.append(f"{path}.activate: expected boolean")
            if action == "create":
                description = goal_update.get("description")
                if not isinstance(description, str) or not description.strip():
                    errors.append(
                        f"{path}.description: create requires a description"
                    )
                if goal_update.get("blocked_reason") is not None:
                    errors.append(
                        f"{path}.blocked_reason: create cannot be blocked"
                    )
            else:
                if goal_update.get("description") is not None:
                    errors.append(
                        f"{path}.description: valid only for create"
                    )
                if goal_update.get("depends_on") not in ([], None):
                    errors.append(
                        f"{path}.depends_on: valid only for create"
                    )
                if goal_update.get("artifact_ids") not in ([], None):
                    errors.append(
                        f"{path}.artifact_ids: valid only for create"
                    )
                if goal_update.get("activate") is not False:
                    errors.append(f"{path}.activate: valid only for create")
                reason = goal_update.get("blocked_reason")
                if action == "block":
                    if not isinstance(reason, str) or not reason.strip():
                        errors.append(
                            f"{path}.blocked_reason: block requires a reason"
                        )
                elif reason is not None:
                    errors.append(
                        f"{path}.blocked_reason: valid only for block"
                    )
    if role is not Role.CAPTAIN and goal_update is not None:
        errors.append(f"$.goal_update: {role.value} may not update goals")

    refusal = value.get("refusal")
    if refusal is not None:
        path = "$.refusal"
        if not isinstance(refusal, Mapping):
            errors.append(f"{path}: expected object or null")
        else:
            _exact_keys(refusal, {"kind", "message", "retryable"}, path, errors)
            for field in ("kind", "message"):
                if not isinstance(refusal.get(field), str):
                    errors.append(f"{path}.{field}: expected string")
            if not isinstance(refusal.get("retryable"), bool):
                errors.append(f"{path}.retryable: expected boolean")
    if value.get("status") == "refused" and refusal is None:
        errors.append("$.refusal: refused status requires refusal details")
    if value.get("status") != "refused" and refusal is not None:
        errors.append("$.refusal: only refused status may include refusal details")

    return ContractValidation(not errors, tuple(errors), value)


def role_prompt(role: Role, user_prompt: str) -> str:
    """Wrap a human/problem prompt with deterministic batch-role rules."""

    spec = ROLE_SPECS[role]
    write_rule = (
        "You may write only challenge-local analysis artifacts requested by the task."
        if spec.may_write_artifacts
        else "You are read-only. Do not modify challenge or workspace files."
    )
    decision_rule = (
        "You must propose the engine's next_stage in decision."
        if role is Role.CAPTAIN
        else "You may not decide the engine stage; decision must be null."
    )
    independence_rule = (
        "Work independently from the Builder conversation; judge only supplied evidence."
        if role is Role.FALSIFIER
        else ""
    )
    return "\n".join(
        part
        for part in (
            f"You are the CTF-OS deterministic Batch role: {role.value}.",
            spec.purpose,
            "Do not spawn or delegate to subagents in Batch mode.",
            write_rule,
            decision_rule,
            independence_rule,
            "Use only these provenance values: executed, tool_inferred, model_claimed, "
            "external_doc, operator.",
            "Every hypothesis must include falsifier, keep_if, and drop_if before execution.",
            (
                "Only Captain may emit goal_update; activating a new goal "
                "atomically parks the previous active goal."
            ),
            (
                "Use hypothesis_updates and evaluations for existing canonical "
                "records. Never infer kept/dropped from exit status or free-text "
                "keep_if/drop_if."
            ),
            (
                "confirmed hypotheses require canonical executed fact, run, "
                "and immutable artifact evidence; model claims alone are invalid."
            ),
            "Report any possible flag in flag_candidates immediately; never submit a flag.",
            "Return only the requested JSON object. Do not add Markdown fences or extra keys.",
            "",
            "Problem-solving prompt:",
            user_prompt,
        )
        if part
    )
