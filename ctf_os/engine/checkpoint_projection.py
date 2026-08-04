"""Bounded, command-free references used by durable checkpoints.

Experiments remain canonical in ``state.json``.  A checkpoint only needs a
stable pointer to an experiment and a fingerprint that detects a changed
command; copying the command itself makes every later state generation and
handoff unnecessarily large.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable

from ctf_os.models import Experiment, ModelValidationError
from ctf_os.store.atomic import canonical_json_record


CHECKPOINT_ACTION_PROJECTION_KEY = "experiment_action_projection"
CHECKPOINT_ACTION_PROJECTION_SCHEMA_VERSION = 2
MANAGED_REGISTERED_SELECTION_KEY = "managed_registered_selection_v1"
MANAGED_REGISTERED_SELECTION_SCHEMA_VERSION = 1
MAX_MANAGED_REGISTERED_CONDITION_BYTES = 2048
MAX_MANAGED_REGISTERED_CONTRACT_BYTES = 8192
_DIRECT_EXPERIMENT_ID = re.compile(
    r"\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z"
)
_ACTION_REFERENCE = re.compile(
    r"\Aexperiment:([A-Za-z0-9][A-Za-z0-9_.:-]{0,255})"
    r"@sha256:([0-9a-f]{64})\Z"
)
_HASHED_ACTION_REFERENCE = re.compile(
    r"\Aexperiment_id_sha256:([0-9a-f]{64})"
    r"@command_sha256:([0-9a-f]{64})\Z"
)


def experiment_command_sha256(experiment: Experiment) -> str:
    """Fingerprint an exact canonical experiment command without rendering it."""

    try:
        payload = experiment.command.encode("utf-8", errors="strict")
    except UnicodeError as error:
        raise ModelValidationError(
            f"experiment {experiment.id} command is not valid UTF-8"
        ) from error
    return hashlib.sha256(payload).hexdigest()


def experiment_contract_sha256(experiment: Experiment) -> str:
    """Fingerprint the exact model-authored semantic conditions."""

    return hashlib.sha256(
        canonical_json_record(
            {
                "drop_if": experiment.drop_if,
                "expected_observation": experiment.expected_observation,
                "keep_if": experiment.keep_if,
            }
        ).encode("ascii")
    ).hexdigest()


def managed_registered_selection_binding(
    experiment: Experiment,
) -> dict[str, object]:
    """Build the command-free durable binding for a Captain selection."""

    return {
        "schema_version": MANAGED_REGISTERED_SELECTION_SCHEMA_VERSION,
        "experiment_id": experiment.id,
        "command_sha256": experiment_command_sha256(experiment),
        "contract_sha256": experiment_contract_sha256(experiment),
    }


def managed_registered_selection_matches(
    experiment: Experiment,
    binding: object,
) -> bool:
    """Return whether a binding names this exact canonical experiment."""

    return (
        isinstance(binding, dict)
        and set(binding)
        == {
            "schema_version",
            "experiment_id",
            "command_sha256",
            "contract_sha256",
        }
        and binding == managed_registered_selection_binding(experiment)
    )


def managed_registered_contract_is_bounded(
    experiment: Experiment,
) -> bool:
    """Keep exact worker-facing conditions within a fixed context budget."""

    fields = (
        experiment.expected_observation,
        experiment.keep_if,
        experiment.drop_if,
    )
    try:
        return (
            all(
                len(value.encode("utf-8", errors="strict"))
                <= MAX_MANAGED_REGISTERED_CONDITION_BYTES
                for value in fields
            )
            and len(
                canonical_json_record(
                    {
                        "drop_if": experiment.drop_if,
                        "expected_observation": (
                            experiment.expected_observation
                        ),
                        "keep_if": experiment.keep_if,
                        "resource_class": experiment.resource_class,
                        "timeout_seconds": experiment.timeout_seconds,
                    }
                ).encode("ascii")
            )
            <= MAX_MANAGED_REGISTERED_CONTRACT_BYTES
        )
    except UnicodeError:
        return False


def experiment_id_sha256(experiment: Experiment) -> str:
    return hashlib.sha256(
        experiment.id.encode("utf-8", errors="strict")
    ).hexdigest()


def experiment_id_pointer(experiment: Experiment) -> dict[str, str]:
    if _DIRECT_EXPERIMENT_ID.fullmatch(experiment.id):
        return {"experiment_id": experiment.id}
    return {"experiment_id_sha256": experiment_id_sha256(experiment)}


def checkpoint_action_reference(experiment: Experiment) -> str:
    """Return one bounded reference to the canonical experiment record."""

    command_sha256 = experiment_command_sha256(experiment)
    if _DIRECT_EXPERIMENT_ID.fullmatch(experiment.id):
        return f"experiment:{experiment.id}@sha256:{command_sha256}"
    return (
        f"experiment_id_sha256:{experiment_id_sha256(experiment)}"
        f"@command_sha256:{command_sha256}"
    )


def checkpoint_action_references(
    experiments: Iterable[Experiment],
) -> list[str]:
    return [checkpoint_action_reference(item) for item in experiments]


def parse_checkpoint_action_reference(
    value: str,
) -> tuple[str, str, str] | None:
    """Parse a v1/v2 reference; legacy action text returns ``None``."""

    matched = _ACTION_REFERENCE.fullmatch(value)
    if matched is not None:
        return "id", matched.group(1), matched.group(2)
    matched = _HASHED_ACTION_REFERENCE.fullmatch(value)
    if matched is not None:
        return "id_sha256", matched.group(1), matched.group(2)
    return None


def checkpoint_has_action_projection(extra: object) -> bool:
    if not isinstance(extra, dict):
        return False
    projection = extra.get(CHECKPOINT_ACTION_PROJECTION_KEY)
    if not isinstance(projection, dict):
        return False
    return projection.get("schema_version") in {1, 2}


def checkpoint_action_projection_metadata() -> dict[str, object]:
    """Describe how checkpoint action strings resolve into canonical state."""

    return {
        CHECKPOINT_ACTION_PROJECTION_KEY: {
            "canonical_pointer": "state.json#/experiments",
            "reference_formats": [
                "experiment:<id>@sha256:<command_sha256>",
                (
                    "experiment_id_sha256:<id_sha256>"
                    "@command_sha256:<command_sha256>"
                ),
            ],
            "schema_version": CHECKPOINT_ACTION_PROJECTION_SCHEMA_VERSION,
        }
    }


__all__ = [
    "CHECKPOINT_ACTION_PROJECTION_KEY",
    "CHECKPOINT_ACTION_PROJECTION_SCHEMA_VERSION",
    "MANAGED_REGISTERED_SELECTION_KEY",
    "MANAGED_REGISTERED_SELECTION_SCHEMA_VERSION",
    "MAX_MANAGED_REGISTERED_CONDITION_BYTES",
    "MAX_MANAGED_REGISTERED_CONTRACT_BYTES",
    "checkpoint_has_action_projection",
    "checkpoint_action_projection_metadata",
    "checkpoint_action_reference",
    "checkpoint_action_references",
    "experiment_command_sha256",
    "experiment_contract_sha256",
    "experiment_id_pointer",
    "experiment_id_sha256",
    "managed_registered_selection_binding",
    "managed_registered_contract_is_bounded",
    "managed_registered_selection_matches",
    "parse_checkpoint_action_reference",
]
