"""Fail-closed binding between promotion arms and executed scaffolds.

Promotion manifests already bind a human-selected challenge identity to an
evaluation arm.  This module supplies the independent execution contract used
at solve launch and bundle capture.  It deliberately does not start a
challenge, choose a challenge, call a model, or submit a candidate.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Mapping

from ctf_os.benchmark import CTF_OS_SYSTEM, THIN_SCAFFOLD
from ctf_os.store.atomic import canonical_json_bytes


SCAFFOLD_LAUNCH_SCHEMA_VERSION = 1
SCAFFOLD_LAUNCH_PROTOCOL = "ctfos.execution_scaffold.v1"
SCAFFOLD_LAUNCH_METADATA_KEY = "evaluation_scaffold_launch"
THIN_SOLVE_MODE = "thin"
FULL_SOLVE_MODE = "managed"
ASSISTED_SOLVE_MODE = "assisted"
_ARMS = frozenset({THIN_SCAFFOLD, CTF_OS_SYSTEM})
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_IMAGE_RE = re.compile(r"sha256:[0-9a-f]{64}")
_MAX_TEXT_BYTES = 512


class ScaffoldBindingError(ValueError):
    """A prepared evaluation state and requested scaffold do not agree."""


def _bounded_text(value: object, label: str) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value.encode("utf-8", errors="strict")) > _MAX_TEXT_BYTES
        or any(ord(character) < 0x20 for character in value)
        or "\x7f" in value
    ):
        raise ScaffoldBindingError(
            f"{label} must be bounded non-empty printable text"
        )
    return value


def _sha256(value: object, label: str) -> str:
    text = _bounded_text(value, label)
    if _SHA256_RE.fullmatch(text) is None:
        raise ScaffoldBindingError(
            f"{label} must be a lowercase SHA-256 digest"
        )
    return text


def _image_digest(value: object) -> str:
    text = _bounded_text(value, "runtime_image_digest")
    if _IMAGE_RE.fullmatch(text) is None:
        raise ScaffoldBindingError(
            "runtime_image_digest must be an exact image ID"
        )
    return text


def _utc_timestamp(value: object) -> str:
    text = _bounded_text(value, "launched_at")
    if not text.endswith("Z"):
        raise ScaffoldBindingError("launched_at must be a UTC Z timestamp")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as error:
        raise ScaffoldBindingError(
            "launched_at must be a valid timestamp"
        ) from error
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise ScaffoldBindingError("launched_at must be UTC")
    return text


def _now() -> str:
    return (
        datetime.now(UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def solve_mode_arm(
    metadata: Mapping[str, object],
    solve_mode: str,
) -> str | None:
    """Return the requested arm and reject relabeling on prepared states."""

    if solve_mode == THIN_SOLVE_MODE:
        requested = THIN_SCAFFOLD
    elif solve_mode == FULL_SOLVE_MODE:
        requested = CTF_OS_SYSTEM
    elif solve_mode == ASSISTED_SOLVE_MODE:
        requested = None
    else:
        raise ScaffoldBindingError("unsupported solve scaffold mode")

    prepared = metadata.get("evaluation_prepared")
    if prepared is not True:
        return requested
    declared = metadata.get("evaluation_system")
    if declared not in _ARMS:
        raise ScaffoldBindingError(
            "prepared evaluation state has an invalid arm"
        )
    if requested is None:
        raise ScaffoldBindingError(
            "prepared evaluation sessions cannot use unbound assisted mode"
        )
    if requested != declared:
        raise ScaffoldBindingError(
            "requested solve scaffold does not match the frozen evaluation arm"
        )
    return requested


@dataclass(frozen=True, slots=True)
class ScaffoldLaunchBinding:
    arm: str
    benchmark_id: str
    case_id: str
    session_id: str
    manifest_sha256: str
    source_manifest_sha256: str
    configuration_epoch: int
    model_id: str
    runtime_image_digest: str
    tool_manifest_sha256: str
    model_config_sha256: str
    command_contract_sha256: str

    def core_dict(self) -> dict[str, object]:
        return {
            "arm": self.arm,
            "benchmark_id": self.benchmark_id,
            "case_id": self.case_id,
            "command_contract_sha256": self.command_contract_sha256,
            "configuration_epoch": self.configuration_epoch,
            "manifest_sha256": self.manifest_sha256,
            "model_config_sha256": self.model_config_sha256,
            "model_id": self.model_id,
            "protocol": SCAFFOLD_LAUNCH_PROTOCOL,
            "runtime_image_digest": self.runtime_image_digest,
            "session_id": self.session_id,
            "source_manifest_sha256": self.source_manifest_sha256,
            "tool_manifest_sha256": self.tool_manifest_sha256,
        }

    @property
    def binding_sha256(self) -> str:
        return hashlib.sha256(
            canonical_json_bytes(self.core_dict())
        ).hexdigest()

    def to_record(self, *, launched_at: str | None = None) -> dict[str, object]:
        record = {
            "schema_version": SCAFFOLD_LAUNCH_SCHEMA_VERSION,
            **self.core_dict(),
            "binding_sha256": self.binding_sha256,
            "launched_at": launched_at or _now(),
        }
        record["record_sha256"] = hashlib.sha256(
            canonical_json_bytes(record)
        ).hexdigest()
        return record


def build_scaffold_launch_binding(
    *,
    metadata: Mapping[str, object],
    configuration_epoch: int,
    arm: str,
    model_id: str,
    runtime_image_digest: str,
    command_contract_sha256: str,
) -> ScaffoldLaunchBinding:
    """Build one launch binding from an already prepared evaluation state."""

    if metadata.get("evaluation_prepared") is not True:
        raise ScaffoldBindingError(
            "scaffold launch binding requires a prepared evaluation state"
        )
    if arm not in _ARMS or metadata.get("evaluation_system") != arm:
        raise ScaffoldBindingError(
            "scaffold launch arm does not match prepared evaluation metadata"
        )
    if (
        type(configuration_epoch) is not int
        or configuration_epoch < 0
    ):
        raise ScaffoldBindingError(
            "configuration_epoch must be a non-negative integer"
        )
    image = _image_digest(runtime_image_digest)
    expected_image = _sha256(
        metadata.get("evaluation_image_sha256"),
        "evaluation_image_sha256",
    )
    if image.removeprefix("sha256:") != expected_image:
        raise ScaffoldBindingError(
            "runtime image does not match the frozen evaluation image"
        )
    expected_model = _bounded_text(
        metadata.get("evaluation_model"),
        "evaluation_model",
    )
    selected_model = _bounded_text(model_id, "model_id")
    if selected_model != expected_model:
        raise ScaffoldBindingError(
            "launch model does not match the frozen evaluation model"
        )
    return ScaffoldLaunchBinding(
        arm=arm,
        benchmark_id=_bounded_text(
            metadata.get("evaluation_benchmark_id"),
            "evaluation_benchmark_id",
        ),
        case_id=_bounded_text(
            metadata.get("evaluation_case_id"),
            "evaluation_case_id",
        ),
        session_id=_bounded_text(
            metadata.get("evaluation_session_id"),
            "evaluation_session_id",
        ),
        manifest_sha256=_sha256(
            metadata.get("evaluation_manifest_sha256"),
            "evaluation_manifest_sha256",
        ),
        source_manifest_sha256=_sha256(
            metadata.get("source_manifest_sha256"),
            "source_manifest_sha256",
        ),
        configuration_epoch=configuration_epoch,
        model_id=selected_model,
        runtime_image_digest=image,
        tool_manifest_sha256=_sha256(
            metadata.get("evaluation_tool_manifest_sha256"),
            "evaluation_tool_manifest_sha256",
        ),
        model_config_sha256=_sha256(
            metadata.get("evaluation_model_config_sha256"),
            "evaluation_model_config_sha256",
        ),
        command_contract_sha256=_sha256(
            command_contract_sha256,
            "command_contract_sha256",
        ),
    )


def parse_scaffold_launch_record(
    value: object,
) -> tuple[ScaffoldLaunchBinding, str]:
    """Strictly parse and authenticate one canonical launch record."""

    required = {
        "arm",
        "benchmark_id",
        "binding_sha256",
        "case_id",
        "command_contract_sha256",
        "configuration_epoch",
        "launched_at",
        "manifest_sha256",
        "model_config_sha256",
        "model_id",
        "protocol",
        "record_sha256",
        "runtime_image_digest",
        "schema_version",
        "session_id",
        "source_manifest_sha256",
        "tool_manifest_sha256",
    }
    if type(value) is not dict or set(value) != required:
        raise ScaffoldBindingError(
            "scaffold launch record has a non-canonical schema"
        )
    if (
        value.get("schema_version") != SCAFFOLD_LAUNCH_SCHEMA_VERSION
        or value.get("protocol") != SCAFFOLD_LAUNCH_PROTOCOL
        or value.get("arm") not in _ARMS
        or type(value.get("configuration_epoch")) is not int
        or value["configuration_epoch"] < 0
    ):
        raise ScaffoldBindingError(
            "scaffold launch record has invalid protocol fields"
        )
    binding = ScaffoldLaunchBinding(
        arm=str(value["arm"]),
        benchmark_id=_bounded_text(
            value["benchmark_id"], "benchmark_id"
        ),
        case_id=_bounded_text(value["case_id"], "case_id"),
        session_id=_bounded_text(value["session_id"], "session_id"),
        manifest_sha256=_sha256(
            value["manifest_sha256"], "manifest_sha256"
        ),
        source_manifest_sha256=_sha256(
            value["source_manifest_sha256"],
            "source_manifest_sha256",
        ),
        configuration_epoch=int(value["configuration_epoch"]),
        model_id=_bounded_text(value["model_id"], "model_id"),
        runtime_image_digest=_image_digest(
            value["runtime_image_digest"]
        ),
        tool_manifest_sha256=_sha256(
            value["tool_manifest_sha256"],
            "tool_manifest_sha256",
        ),
        model_config_sha256=_sha256(
            value["model_config_sha256"],
            "model_config_sha256",
        ),
        command_contract_sha256=_sha256(
            value["command_contract_sha256"],
            "command_contract_sha256",
        ),
    )
    observed_hash = _sha256(
        value["binding_sha256"], "binding_sha256"
    )
    if observed_hash != binding.binding_sha256:
        raise ScaffoldBindingError(
            "scaffold launch binding hash does not match"
        )
    launched_at = _utc_timestamp(value["launched_at"])
    recorded_hash = _sha256(value["record_sha256"], "record_sha256")
    hash_input = dict(value)
    del hash_input["record_sha256"]
    if recorded_hash != hashlib.sha256(
        canonical_json_bytes(hash_input)
    ).hexdigest():
        raise ScaffoldBindingError(
            "scaffold launch record hash does not match"
        )
    return binding, launched_at


def validate_scaffold_launch_record(
    *,
    metadata: Mapping[str, object],
    configuration_epoch: int,
    value: object,
    expected_arm: str,
    expected_command_contract_sha256: str,
) -> ScaffoldLaunchBinding:
    """Rebind a stored launch record to the current prepared state."""

    binding, _launched_at = parse_scaffold_launch_record(value)
    expected = build_scaffold_launch_binding(
        metadata=metadata,
        configuration_epoch=configuration_epoch,
        arm=expected_arm,
        model_id=binding.model_id,
        runtime_image_digest=binding.runtime_image_digest,
        command_contract_sha256=expected_command_contract_sha256,
    )
    if binding != expected:
        raise ScaffoldBindingError(
            "scaffold launch record is stale or belongs to another session"
        )
    return binding


__all__ = [
    "ASSISTED_SOLVE_MODE",
    "FULL_SOLVE_MODE",
    "SCAFFOLD_LAUNCH_METADATA_KEY",
    "SCAFFOLD_LAUNCH_PROTOCOL",
    "SCAFFOLD_LAUNCH_SCHEMA_VERSION",
    "ScaffoldBindingError",
    "ScaffoldLaunchBinding",
    "THIN_SOLVE_MODE",
    "build_scaffold_launch_binding",
    "parse_scaffold_launch_record",
    "solve_mode_arm",
    "validate_scaffold_launch_record",
]
