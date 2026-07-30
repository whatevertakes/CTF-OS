"""Engine-owned bindings for one diagnostic Pwn runtime snapshot replay.

The model cannot choose the command, signal, image, producer, or target
arguments.  A recipe binds one deterministic child probe to one confirmed
parent crash evaluation.  The aggregate evaluation is diagnostic only:
``CAPTURED`` does not prove a crash, leak, primitive, exploit, proof, or stage
transition.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath

from ctf_os.contracts.pwn_runtime_snapshot_v1 import (
    PWN_RUNTIME_SNAPSHOT_V1_ALLOWED_SIGNALS,
    PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_FINGERPRINT,
    PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_ID,
    PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_VERSION,
    PWN_RUNTIME_SNAPSHOT_V1_DOCUMENT_TRANSPORT,
    PWN_RUNTIME_SNAPSHOT_V1_FAILURE_CODES,
    PWN_RUNTIME_SNAPSHOT_V1_MAX_DOCUMENT_BYTES,
    PWN_RUNTIME_SNAPSHOT_V1_MAX_PAYLOAD_BYTES,
    PWN_RUNTIME_SNAPSHOT_V1_MAX_SOURCE_BYTES,
    PWN_RUNTIME_SNAPSHOT_V1_PROTOCOL,
    PWN_RUNTIME_SNAPSHOT_V1_TARGET_TIMEOUT_SECONDS,
    PwnRuntimeSnapshotV1ContractError,
    PwnRuntimeSnapshotV1Result,
    PwnRuntimeSnapshotV1Status,
    parse_pwn_runtime_snapshot_v1_result,
)


PWN_RUNTIME_SNAPSHOT_RECIPE_SCHEMA_VERSION = 1
PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME = (
    "pwn_runtime_snapshot_v1"
)
PWN_RUNTIME_SNAPSHOT_PRODUCER_INTERPRETER_PATH = "/usr/bin/python3"
PWN_RUNTIME_SNAPSHOT_PRODUCER_PATH = (
    "/opt/ctf-templates/pwn/runtime_snapshot.py"
)
PWN_RUNTIME_SNAPSHOT_PRODUCER_FILE_SHA256 = (
    "e9d0927e42258a589d17b02f94071379"
    "ea015b040051a405cda455ba14879d97"
)
PWN_RUNTIME_SNAPSHOT_SANDBOX_METHOD = "run_clean_proof"
PWN_RUNTIME_SNAPSHOT_NETWORK_POLICY = "none"
PWN_RUNTIME_SNAPSHOT_ONE_SHOT = True
PWN_RUNTIME_SNAPSHOT_INPUT_DESTINATION_LOCATOR = (
    "pwn-runtime-snapshot-v1/payload.bin"
)
PWN_RUNTIME_SNAPSHOT_INPUT_ARGUMENT = (
    f"/work/{PWN_RUNTIME_SNAPSHOT_INPUT_DESTINATION_LOCATOR}"
)
PWN_RUNTIME_SNAPSHOT_CAPABILITY_PROBE_CONTRACT = (
    "ctfos.inspect_pinned_capabilities.v1"
)
PWN_RUNTIME_SNAPSHOT_MAX_RECIPE_BYTES = 64 * 1024
PWN_RUNTIME_SNAPSHOT_MAX_IDENTIFIER_BYTES = 512
PWN_RUNTIME_SNAPSHOT_MAX_LOCATOR_BYTES = 4096
PWN_RUNTIME_SNAPSHOT_MAX_IMAGE_REFERENCE_BYTES = 512
PWN_RUNTIME_SNAPSHOT_MAX_JSON_DEPTH = 12
PWN_RUNTIME_SNAPSHOT_MAX_JSON_NODES = 1024
PWN_RUNTIME_SNAPSHOT_GATE_SCHEMA_VERSION = 1
PWN_RUNTIME_SNAPSHOT_MAX_GATE_BYTES = (
    PWN_RUNTIME_SNAPSHOT_V1_MAX_DOCUMENT_BYTES + 64 * 1024
)
PWN_RUNTIME_SNAPSHOT_ARGV_TEMPLATE = (
    PWN_RUNTIME_SNAPSHOT_PRODUCER_INTERPRETER_PATH,
    PWN_RUNTIME_SNAPSHOT_PRODUCER_PATH,
    "--binary",
    "/challenge/{primary_elf_locator}",
    "--payload",
    PWN_RUNTIME_SNAPSHOT_INPUT_ARGUMENT,
    "--source-manifest-sha256",
    "{source_manifest_sha256}",
    "--source-sha256",
    "{source_sha256}",
    "--source-size-bytes",
    "{source_size_bytes}",
    "--payload-sha256",
    "{payload_sha256}",
    "--payload-size-bytes",
    "{payload_size_bytes}",
    "--parent-crash-recipe-sha256",
    "{parent_crash_recipe_sha256}",
    "--parent-crash-evaluation-sha256",
    "{parent_crash_evaluation_sha256}",
    "--expected-signal-number",
    "{expected_signal_number}",
    "--snapshot-recipe-sha256",
    "{snapshot_recipe_sha256}",
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,511}$")
_TRANSPORT_CODE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
_RECEIPT_OUTCOMES = frozenset(
    {"succeeded", "failed", "timed_out", "cancelled", "interrupted"}
)
_TRANSPORT_CODES = frozenset(
    {
        "invalid_receipt_metadata",
        "receipt_binding_mismatch",
        "producer_transport_failed",
        "stdout_artifact_incomplete",
        "stdout_capture_incomplete",
        "stdout_hash_binding_mismatch",
        "stdout_size_binding_mismatch",
        "producer_document_rejected",
    }
)
_NON_AUTHORITIES = {
    "address_resolution_proven": False,
    "crash_proven": False,
    "exploit_proven": False,
    "leak_proven": False,
    "parent_crash_revalidated": False,
    "primitive_proven": False,
    "proof_satisfied": False,
    "stage_advance_authorized": False,
}
_RECIPE_KEYS = frozenset(
    {
        "schema_version",
        "contract",
        "protocol",
        "configuration_epoch",
        "child_experiment_id",
        "parent",
        "source",
        "payload",
        "runtime",
        "recipe_sha256",
    }
)
_PARENT_KEYS = frozenset(
    {
        "experiment_id",
        "crash_recipe_sha256",
        "crash_evaluation_sha256",
        "expected_signal_number",
    }
)
_SOURCE_KEYS = frozenset(
    {"kind", "locator", "manifest_sha256", "sha256", "size_bytes"}
)
_PAYLOAD_KEYS = frozenset(
    {
        "artifact_id",
        "source_run_id",
        "locator",
        "sha256",
        "size_bytes",
    }
)
_RUNTIME_KEYS = frozenset(
    {
        "argv_template",
        "capability_name",
        "document_transport",
        "image",
        "input_argument",
        "input_destination_locator",
        "network",
        "one_shot",
        "producer_file_sha256",
        "producer_interpreter_path",
        "producer_path",
        "sandbox_method",
        "target_timeout_seconds",
    }
)
_CONTRACT_KEYS = frozenset({"id", "version", "fingerprint"})
_IMAGE_KEYS = frozenset({"reference", "digest"})
_CAPABILITY_KEYS = frozenset(
    {
        "schema_version",
        "probe_contract",
        "image_digest",
        "recipe_sha256",
        "capability_name",
        "attestation",
    }
)
_ATTESTATION_KEYS = frozenset(
    {"schema_version", "contract_id", "contract_version", "path", "sha256"}
)
_RECEIPT_KEYS = frozenset(
    {
        "receipt_id",
        "run_id",
        "outcome",
        "exit_code",
        "timed_out",
        "clean_workspace",
        "one_shot",
        "sandbox_method",
        "network",
        "configuration_epoch",
        "image_digest",
        "recipe_sha256",
        "request_sha256",
        "execution_contract_sha256",
        "capability_attestation_artifact_id",
        "capability_attestation_sha256",
        "producer_capability_name",
        "producer_file_sha256",
        "stdout_artifact_id",
        "stdout_artifact_sha256",
        "stdout_artifact_size_bytes",
        "stderr_artifact_id",
        "stderr_artifact_sha256",
        "stderr_artifact_size_bytes",
        "stderr_capture_placeholder",
        "stdout_drained_bytes",
        "stdout_stored_bytes",
        "stdout_capture_complete",
        "stdout_truncation_known",
        "stdout_truncated",
        "stdout_error",
        "stream_capture_error",
        "orchestration_error",
        "durable_stdout_artifact_complete",
    }
)
_GATE_KEYS = frozenset(
    {
        "schema_version",
        "status",
        "reason_code",
        "captured",
        "authorities",
        "semantic_result",
        "transport_error",
    }
)
_TRANSPORT_ERROR_KEYS = frozenset({"code", "contract_code"})


class PwnRuntimeSnapshotRecipeError(ValueError):
    """A persisted snapshot recipe is malformed or stale."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class PwnRuntimeSnapshotCapabilityAttestationError(ValueError):
    """The pinned image did not attest the exact snapshot producer."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class PwnRuntimeSnapshotGateEvaluationError(ValueError):
    """A persisted gate evaluation is not canonical."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


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


def _exact(value: object, keys: frozenset[str]) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise PwnRuntimeSnapshotRecipeError("invalid_recipe_schema")
    return value


def _validate_tree(value: object) -> None:
    pending = [(value, 1)]
    nodes = 0
    while pending:
        current, depth = pending.pop()
        nodes += 1
        if (
            depth > PWN_RUNTIME_SNAPSHOT_MAX_JSON_DEPTH
            or nodes > PWN_RUNTIME_SNAPSHOT_MAX_JSON_NODES
        ):
            raise PwnRuntimeSnapshotRecipeError(
                "recipe_structure_limit_exceeded"
            )
        if type(current) is dict:
            if any(type(key) is not str for key in current):
                raise PwnRuntimeSnapshotRecipeError(
                    "invalid_recipe_schema"
                )
            pending.extend(
                (item, depth + 1) for item in current.values()
            )
        elif type(current) is list:
            pending.extend((item, depth + 1) for item in current)
        elif type(current) is float:
            if not math.isfinite(current):
                raise PwnRuntimeSnapshotRecipeError(
                    "invalid_recipe_schema"
                )
        elif type(current) not in {str, int, bool, type(None)}:
            raise PwnRuntimeSnapshotRecipeError(
                "invalid_recipe_schema"
            )


def _identifier(value: object, label: str) -> str:
    if (
        type(value) is not str
        or len(value.encode("utf-8", errors="strict"))
        > PWN_RUNTIME_SNAPSHOT_MAX_IDENTIFIER_BYTES
        or _IDENTIFIER.fullmatch(value) is None
    ):
        raise PwnRuntimeSnapshotRecipeError(f"invalid_{label}")
    return value


def _sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise PwnRuntimeSnapshotRecipeError(f"invalid_{label}")
    return value


def _size(value: object, label: str, maximum: int) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise PwnRuntimeSnapshotRecipeError(f"invalid_{label}")
    return value


def _locator(value: object, label: str) -> str:
    if type(value) is not str:
        raise PwnRuntimeSnapshotRecipeError(f"invalid_{label}")
    encoded = value.encode("utf-8", errors="strict")
    parts = value.split("/")
    if (
        not value
        or len(encoded) > PWN_RUNTIME_SNAPSHOT_MAX_LOCATOR_BYTES
        or value.startswith("/")
        or value.endswith("/")
        or "\\" in value
        or "\x00" in value
        or any(
            part in {"", ".", ".."}
            or len(part.encode("utf-8")) > 255
            for part in parts
        )
        or any(
            unicodedata.category(character).startswith("C")
            for character in value
        )
        or PurePosixPath(value).as_posix() != value
    ):
        raise PwnRuntimeSnapshotRecipeError(f"invalid_{label}")
    return value


def _image_reference(value: object) -> str:
    if type(value) is not str:
        raise PwnRuntimeSnapshotRecipeError("invalid_image_reference")
    encoded = value.encode("utf-8", errors="strict")
    if (
        not value
        or value != value.strip()
        or len(encoded) > PWN_RUNTIME_SNAPSHOT_MAX_IMAGE_REFERENCE_BYTES
        or any(
            character.isspace()
            or unicodedata.category(character).startswith("C")
            for character in value
        )
    ):
        raise PwnRuntimeSnapshotRecipeError("invalid_image_reference")
    return value


def pwn_runtime_snapshot_child_experiment_id(
    parent_experiment_id: str,
) -> str:
    """Return the only child id for a parent experiment."""

    parent = _identifier(parent_experiment_id, "parent_experiment_id")
    digest = hashlib.sha256(parent.encode("utf-8")).hexdigest()
    return f"E-pwn-runtime-snapshot-v1-{digest}"


@dataclass(frozen=True, slots=True)
class PwnRuntimeSnapshotRecipe:
    """Immutable dynamic bindings for the fixed one-run diagnostic."""

    configuration_epoch: int
    child_experiment_id: str
    parent_experiment_id: str
    primary_elf_locator: str
    source_manifest_sha256: str
    source_sha256: str
    source_size_bytes: int
    payload_artifact_id: str
    payload_source_run_id: str
    payload_artifact_locator: str
    payload_sha256: str
    payload_size_bytes: int
    parent_crash_recipe_sha256: str
    parent_crash_evaluation_sha256: str
    expected_signal_number: int
    image_reference: str
    image_digest: str
    producer_file_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.configuration_epoch) is not int
            or not 0 <= self.configuration_epoch <= 2**63 - 1
        ):
            raise PwnRuntimeSnapshotRecipeError(
                "invalid_configuration_epoch"
            )
        _identifier(self.parent_experiment_id, "parent_experiment_id")
        _identifier(self.child_experiment_id, "child_experiment_id")
        if self.child_experiment_id != (
            pwn_runtime_snapshot_child_experiment_id(
                self.parent_experiment_id
            )
        ):
            raise PwnRuntimeSnapshotRecipeError(
                "child_experiment_id_mismatch"
            )
        _locator(self.primary_elf_locator, "primary_elf_locator")
        _sha256(
            self.source_manifest_sha256,
            "source_manifest_sha256",
        )
        _sha256(self.source_sha256, "source_sha256")
        _size(
            self.source_size_bytes,
            "source_size_bytes",
            PWN_RUNTIME_SNAPSHOT_V1_MAX_SOURCE_BYTES,
        )
        _identifier(self.payload_artifact_id, "payload_artifact_id")
        _identifier(self.payload_source_run_id, "payload_source_run_id")
        _locator(
            self.payload_artifact_locator,
            "payload_artifact_locator",
        )
        _sha256(self.payload_sha256, "payload_sha256")
        _size(
            self.payload_size_bytes,
            "payload_size_bytes",
            PWN_RUNTIME_SNAPSHOT_V1_MAX_PAYLOAD_BYTES,
        )
        _sha256(
            self.parent_crash_recipe_sha256,
            "parent_crash_recipe_sha256",
        )
        _sha256(
            self.parent_crash_evaluation_sha256,
            "parent_crash_evaluation_sha256",
        )
        if (
            type(self.expected_signal_number) is not int
            or self.expected_signal_number
            not in PWN_RUNTIME_SNAPSHOT_V1_ALLOWED_SIGNALS
        ):
            raise PwnRuntimeSnapshotRecipeError(
                "invalid_expected_signal_number"
            )
        _image_reference(self.image_reference)
        if (
            type(self.image_digest) is not str
            or _IMAGE_DIGEST.fullmatch(self.image_digest) is None
        ):
            raise PwnRuntimeSnapshotRecipeError(
                "invalid_image_digest"
            )
        _sha256(self.producer_file_sha256, "producer_file_sha256")
        if (
            self.producer_file_sha256
            != PWN_RUNTIME_SNAPSHOT_PRODUCER_FILE_SHA256
        ):
            raise PwnRuntimeSnapshotRecipeError(
                "producer_attestation_mismatch"
            )

    def content_dict(self) -> dict[str, object]:
        return {
            "schema_version": (
                PWN_RUNTIME_SNAPSHOT_RECIPE_SCHEMA_VERSION
            ),
            "contract": {
                "id": PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_ID,
                "version": PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_VERSION,
                "fingerprint": (
                    PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_FINGERPRINT
                ),
            },
            "protocol": PWN_RUNTIME_SNAPSHOT_V1_PROTOCOL,
            "configuration_epoch": self.configuration_epoch,
            "child_experiment_id": self.child_experiment_id,
            "parent": {
                "experiment_id": self.parent_experiment_id,
                "crash_recipe_sha256": (
                    self.parent_crash_recipe_sha256
                ),
                "crash_evaluation_sha256": (
                    self.parent_crash_evaluation_sha256
                ),
                "expected_signal_number": (
                    self.expected_signal_number
                ),
            },
            "source": {
                "kind": "immutable_primary_elf",
                "locator": self.primary_elf_locator,
                "manifest_sha256": self.source_manifest_sha256,
                "sha256": self.source_sha256,
                "size_bytes": self.source_size_bytes,
            },
            "payload": {
                "artifact_id": self.payload_artifact_id,
                "source_run_id": self.payload_source_run_id,
                "locator": self.payload_artifact_locator,
                "sha256": self.payload_sha256,
                "size_bytes": self.payload_size_bytes,
            },
            "runtime": {
                "argv_template": list(
                    PWN_RUNTIME_SNAPSHOT_ARGV_TEMPLATE
                ),
                "capability_name": (
                    PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME
                ),
                "document_transport": (
                    PWN_RUNTIME_SNAPSHOT_V1_DOCUMENT_TRANSPORT
                ),
                "image": {
                    "reference": self.image_reference,
                    "digest": self.image_digest,
                },
                "input_argument": (
                    PWN_RUNTIME_SNAPSHOT_INPUT_ARGUMENT
                ),
                "input_destination_locator": (
                    PWN_RUNTIME_SNAPSHOT_INPUT_DESTINATION_LOCATOR
                ),
                "network": PWN_RUNTIME_SNAPSHOT_NETWORK_POLICY,
                "one_shot": PWN_RUNTIME_SNAPSHOT_ONE_SHOT,
                "producer_file_sha256": self.producer_file_sha256,
                "producer_interpreter_path": (
                    PWN_RUNTIME_SNAPSHOT_PRODUCER_INTERPRETER_PATH
                ),
                "producer_path": PWN_RUNTIME_SNAPSHOT_PRODUCER_PATH,
                "sandbox_method": (
                    PWN_RUNTIME_SNAPSHOT_SANDBOX_METHOD
                ),
                "target_timeout_seconds": (
                    PWN_RUNTIME_SNAPSHOT_V1_TARGET_TIMEOUT_SECONDS
                ),
            },
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

    def canonical_bytes(self) -> bytes:
        payload = _canonical_json_bytes(self.to_dict())
        if len(payload) > PWN_RUNTIME_SNAPSHOT_MAX_RECIPE_BYTES:
            raise PwnRuntimeSnapshotRecipeError(
                "recipe_size_exceeded"
            )
        return payload

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
    ) -> "PwnRuntimeSnapshotRecipe":
        if type(value) is not dict:
            raise PwnRuntimeSnapshotRecipeError(
                "invalid_recipe_schema"
            )
        _validate_tree(value)
        try:
            encoded = _canonical_json_bytes(value)
        except (RecursionError, TypeError, UnicodeError, ValueError) as error:
            raise PwnRuntimeSnapshotRecipeError(
                "invalid_recipe_schema"
            ) from error
        if len(encoded) > PWN_RUNTIME_SNAPSHOT_MAX_RECIPE_BYTES:
            raise PwnRuntimeSnapshotRecipeError(
                "recipe_size_exceeded"
            )
        root = _exact(value, _RECIPE_KEYS)
        contract = _exact(root["contract"], _CONTRACT_KEYS)
        parent = _exact(root["parent"], _PARENT_KEYS)
        source = _exact(root["source"], _SOURCE_KEYS)
        payload = _exact(root["payload"], _PAYLOAD_KEYS)
        runtime = _exact(root["runtime"], _RUNTIME_KEYS)
        image = _exact(runtime["image"], _IMAGE_KEYS)
        supplied = _sha256(root["recipe_sha256"], "recipe_sha256")
        try:
            recipe = cls(
                configuration_epoch=root["configuration_epoch"],
                child_experiment_id=root["child_experiment_id"],
                parent_experiment_id=parent["experiment_id"],
                primary_elf_locator=source["locator"],
                source_manifest_sha256=source["manifest_sha256"],
                source_sha256=source["sha256"],
                source_size_bytes=source["size_bytes"],
                payload_artifact_id=payload["artifact_id"],
                payload_source_run_id=payload["source_run_id"],
                payload_artifact_locator=payload["locator"],
                payload_sha256=payload["sha256"],
                payload_size_bytes=payload["size_bytes"],
                parent_crash_recipe_sha256=parent[
                    "crash_recipe_sha256"
                ],
                parent_crash_evaluation_sha256=parent[
                    "crash_evaluation_sha256"
                ],
                expected_signal_number=parent[
                    "expected_signal_number"
                ],
                image_reference=image["reference"],
                image_digest=image["digest"],
                producer_file_sha256=runtime[
                    "producer_file_sha256"
                ],
            )
        except KeyError as error:
            raise PwnRuntimeSnapshotRecipeError(
                "invalid_recipe_schema"
            ) from error
        if supplied != recipe.recipe_sha256:
            raise PwnRuntimeSnapshotRecipeError(
                "recipe_hash_mismatch"
            )
        if value != recipe.to_dict():
            raise PwnRuntimeSnapshotRecipeError(
                "recipe_contract_mismatch"
            )
        return recipe

    def argv(self) -> tuple[str, ...]:
        values = {
            "primary_elf_locator": self.primary_elf_locator,
            "source_manifest_sha256": self.source_manifest_sha256,
            "source_sha256": self.source_sha256,
            "source_size_bytes": str(self.source_size_bytes),
            "payload_sha256": self.payload_sha256,
            "payload_size_bytes": str(self.payload_size_bytes),
            "parent_crash_recipe_sha256": (
                self.parent_crash_recipe_sha256
            ),
            "parent_crash_evaluation_sha256": (
                self.parent_crash_evaluation_sha256
            ),
            "expected_signal_number": str(
                self.expected_signal_number
            ),
            "snapshot_recipe_sha256": self.recipe_sha256,
        }
        return tuple(
            token.format_map(values)
            for token in PWN_RUNTIME_SNAPSHOT_ARGV_TEMPLATE
        )


def _expected_attestation() -> dict[str, object]:
    return {
        "schema_version": 1,
        "contract_id": PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_ID,
        "contract_version": PWN_RUNTIME_SNAPSHOT_V1_CONTRACT_VERSION,
        "path": PWN_RUNTIME_SNAPSHOT_PRODUCER_PATH,
        "sha256": PWN_RUNTIME_SNAPSHOT_PRODUCER_FILE_SHA256,
    }


@dataclass(frozen=True, slots=True)
class PwnRuntimeSnapshotCapabilityAttestation:
    image_digest: str
    recipe_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.image_digest) is not str
            or _IMAGE_DIGEST.fullmatch(self.image_digest) is None
            or type(self.recipe_sha256) is not str
            or _SHA256.fullmatch(self.recipe_sha256) is None
        ):
            raise PwnRuntimeSnapshotCapabilityAttestationError(
                "invalid_attestation_binding"
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "probe_contract": (
                PWN_RUNTIME_SNAPSHOT_CAPABILITY_PROBE_CONTRACT
            ),
            "image_digest": self.image_digest,
            "recipe_sha256": self.recipe_sha256,
            "capability_name": (
                PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME
            ),
            "attestation": _expected_attestation(),
        }

    def canonical_bytes(self) -> bytes:
        return _canonical_json_bytes(self.to_dict())

    @property
    def evidence_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
    ) -> "PwnRuntimeSnapshotCapabilityAttestation":
        if type(value) is not dict or set(value) != _CAPABILITY_KEYS:
            raise PwnRuntimeSnapshotCapabilityAttestationError(
                "invalid_attestation_schema"
            )
        if (
            value.get("schema_version") != 1
            or value.get("probe_contract")
            != PWN_RUNTIME_SNAPSHOT_CAPABILITY_PROBE_CONTRACT
            or value.get("capability_name")
            != PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME
            or value.get("attestation") != _expected_attestation()
        ):
            raise PwnRuntimeSnapshotCapabilityAttestationError(
                "attestation_contract_mismatch"
            )
        result = cls(
            image_digest=value["image_digest"],
            recipe_sha256=value["recipe_sha256"],
        )
        if value != result.to_dict():
            raise PwnRuntimeSnapshotCapabilityAttestationError(
                "attestation_contract_mismatch"
            )
        return result


def normalize_pwn_runtime_snapshot_capability_attestation(
    report: Mapping[str, object],
    *,
    image_digest: str,
    recipe_sha256: str,
) -> PwnRuntimeSnapshotCapabilityAttestation:
    result = PwnRuntimeSnapshotCapabilityAttestation(
        image_digest=image_digest,
        recipe_sha256=recipe_sha256,
    )
    if (
        type(report) is not dict
        or report.get("ok") is not True
        or report.get("image_digest") != image_digest
        or type(report.get("available")) is not list
        or any(
            type(item) is not str for item in report["available"]
        )
        or PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME
        not in report["available"]
        or type(report.get("attestations")) is not dict
        or report["attestations"].get(
            PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME
        )
        != _expected_attestation()
        or type(report.get("attestation_errors")) is not dict
        or PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME
        in report["attestation_errors"]
    ):
        raise PwnRuntimeSnapshotCapabilityAttestationError(
            "invalid_capability_report"
        )
    return result


def _receipt_identifier(value: object, label: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"invalid receipt {label}")
    return value


def _receipt_sha(value: object, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ValueError(f"invalid receipt {label}")
    return value


@dataclass(frozen=True, slots=True)
class PwnRuntimeSnapshotReceiptMetadata:
    """Transport metadata for the single snapshot producer run."""

    receipt_id: str
    run_id: str
    outcome: str
    exit_code: int | None
    timed_out: bool
    clean_workspace: bool
    one_shot: bool
    sandbox_method: str
    network: str
    configuration_epoch: int
    image_digest: str
    recipe_sha256: str
    request_sha256: str
    execution_contract_sha256: str
    capability_attestation_artifact_id: str
    capability_attestation_sha256: str
    producer_capability_name: str
    producer_file_sha256: str
    stdout_artifact_id: str | None
    stdout_artifact_sha256: str | None
    stdout_artifact_size_bytes: int | None
    stderr_artifact_id: str
    stderr_artifact_sha256: str
    stderr_artifact_size_bytes: int
    stderr_capture_placeholder: bool
    stdout_drained_bytes: int
    stdout_stored_bytes: int
    stdout_capture_complete: bool
    stdout_truncation_known: bool
    stdout_truncated: bool | None
    stdout_error: str | None
    stream_capture_error: str | None
    orchestration_error: str | None
    durable_stdout_artifact_complete: bool

    def __post_init__(self) -> None:
        _receipt_identifier(self.receipt_id, "receipt_id")
        _receipt_identifier(self.run_id, "run_id")
        if self.outcome not in _RECEIPT_OUTCOMES:
            raise ValueError("invalid receipt outcome")
        if self.exit_code is not None and (
            type(self.exit_code) is not int
            or not -255 <= self.exit_code <= 255
        ):
            raise ValueError("invalid receipt exit_code")
        for name in (
            "timed_out",
            "clean_workspace",
            "one_shot",
            "stderr_capture_placeholder",
            "stdout_capture_complete",
            "stdout_truncation_known",
            "durable_stdout_artifact_complete",
        ):
            if type(getattr(self, name)) is not bool:
                raise ValueError(f"invalid receipt {name}")
        if (
            self.stdout_truncated is not None
            and type(self.stdout_truncated) is not bool
        ):
            raise ValueError("invalid receipt stdout_truncated")
        if (
            type(self.configuration_epoch) is not int
            or not 0 <= self.configuration_epoch <= 2**63 - 1
            or type(self.image_digest) is not str
            or _IMAGE_DIGEST.fullmatch(self.image_digest) is None
        ):
            raise ValueError("invalid receipt execution binding")
        for name in (
            "recipe_sha256",
            "request_sha256",
            "execution_contract_sha256",
            "capability_attestation_sha256",
            "producer_file_sha256",
        ):
            _receipt_sha(getattr(self, name), name)
        _receipt_identifier(
            self.capability_attestation_artifact_id,
            "capability_attestation_artifact_id",
        )
        if not self.sandbox_method or not self.network:
            raise ValueError("invalid receipt sandbox binding")
        if (
            self.stdout_artifact_id is not None
            and not _IDENTIFIER.fullmatch(self.stdout_artifact_id)
        ):
            raise ValueError("invalid receipt stdout_artifact_id")
        if self.stdout_artifact_sha256 is not None:
            _receipt_sha(
                self.stdout_artifact_sha256,
                "stdout_artifact_sha256",
            )
        _receipt_identifier(
            self.stderr_artifact_id,
            "stderr_artifact_id",
        )
        _receipt_sha(
            self.stderr_artifact_sha256,
            "stderr_artifact_sha256",
        )
        if (
            type(self.stderr_artifact_size_bytes) is not int
            or self.stderr_artifact_size_bytes < 0
        ):
            raise ValueError(
                "invalid receipt stderr_artifact_size_bytes"
            )
        for name in (
            "stdout_artifact_size_bytes",
            "stdout_drained_bytes",
            "stdout_stored_bytes",
        ):
            value = getattr(self, name)
            if (
                value is None
                and name == "stdout_artifact_size_bytes"
            ):
                continue
            if type(value) is not int or value < 0:
                raise ValueError(f"invalid receipt {name}")
        for name in (
            "stdout_error",
            "stream_capture_error",
            "orchestration_error",
        ):
            value = getattr(self, name)
            if value is not None and (
                type(value) is not str
                or not value
                or len(value.encode("utf-8")) > 512
            ):
                raise ValueError(f"invalid receipt {name}")

    def to_dict(self) -> dict[str, object]:
        return {
            key: getattr(self, key) for key in sorted(_RECEIPT_KEYS)
        }

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
    ) -> "PwnRuntimeSnapshotReceiptMetadata":
        if type(value) is not dict or set(value) != _RECEIPT_KEYS:
            raise ValueError("invalid receipt metadata schema")
        return cls(**value)


@dataclass(frozen=True, slots=True)
class PwnRuntimeSnapshotTransportError:
    code: str
    contract_code: str | None = None

    def __post_init__(self) -> None:
        if self.code not in _TRANSPORT_CODES:
            raise PwnRuntimeSnapshotGateEvaluationError(
                "invalid_transport_error"
            )
        if self.contract_code is not None and (
            self.code != "producer_document_rejected"
            or self.contract_code
            not in PWN_RUNTIME_SNAPSHOT_V1_FAILURE_CODES
        ):
            raise PwnRuntimeSnapshotGateEvaluationError(
                "invalid_transport_error"
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "contract_code": self.contract_code,
        }

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
    ) -> "PwnRuntimeSnapshotTransportError":
        if type(value) is not dict or set(value) != _TRANSPORT_ERROR_KEYS:
            raise PwnRuntimeSnapshotGateEvaluationError(
                "invalid_transport_error"
            )
        return cls(
            code=value["code"],
            contract_code=value["contract_code"],
        )


@dataclass(frozen=True, slots=True)
class PwnRuntimeSnapshotGateEvaluation:
    """Canonical diagnostic result or a distinct transport failure."""

    status: PwnRuntimeSnapshotV1Status
    reason_code: str
    semantic_result: PwnRuntimeSnapshotV1Result | None
    transport_error: PwnRuntimeSnapshotTransportError | None

    def __post_init__(self) -> None:
        if type(self.status) is not PwnRuntimeSnapshotV1Status:
            raise PwnRuntimeSnapshotGateEvaluationError(
                "invalid_gate_status"
            )
        if type(self.reason_code) is not str:
            raise PwnRuntimeSnapshotGateEvaluationError(
                "invalid_gate_reason"
            )
        if (self.semantic_result is None) == (
            self.transport_error is None
        ):
            raise PwnRuntimeSnapshotGateEvaluationError(
                "invalid_gate_branch"
            )
        if self.semantic_result is not None:
            if (
                type(self.semantic_result)
                is not PwnRuntimeSnapshotV1Result
                or self.status is not self.semantic_result.status
                or self.reason_code
                != self.semantic_result.reason_code
            ):
                raise PwnRuntimeSnapshotGateEvaluationError(
                    "semantic_projection_mismatch"
                )
        elif (
            self.status is not PwnRuntimeSnapshotV1Status.ERROR
            or self.transport_error is None
            or self.reason_code
            != f"transport_{self.transport_error.code}"
        ):
            raise PwnRuntimeSnapshotGateEvaluationError(
                "transport_projection_mismatch"
            )

    @property
    def captured(self) -> bool:
        return (
            self.status is PwnRuntimeSnapshotV1Status.CAPTURED
            and self.semantic_result is not None
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": (
                PWN_RUNTIME_SNAPSHOT_GATE_SCHEMA_VERSION
            ),
            "status": self.status.value,
            "reason_code": self.reason_code,
            "captured": self.captured,
            "authorities": dict(_NON_AUTHORITIES),
            "semantic_result": (
                self.semantic_result.to_dict()
                if self.semantic_result is not None
                else None
            ),
            "transport_error": (
                self.transport_error.to_dict()
                if self.transport_error is not None
                else None
            ),
        }

    def canonical_bytes(self) -> bytes:
        payload = _canonical_json_bytes(self.to_dict())
        if len(payload) > PWN_RUNTIME_SNAPSHOT_MAX_GATE_BYTES:
            raise PwnRuntimeSnapshotGateEvaluationError(
                "gate_size_exceeded"
            )
        return payload

    @property
    def evidence_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
        *,
        recipe: PwnRuntimeSnapshotRecipe,
    ) -> "PwnRuntimeSnapshotGateEvaluation":
        if type(value) is not dict or set(value) != _GATE_KEYS:
            raise PwnRuntimeSnapshotGateEvaluationError(
                "invalid_gate_schema"
            )
        if (
            value.get("schema_version")
            != PWN_RUNTIME_SNAPSHOT_GATE_SCHEMA_VERSION
            or value.get("authorities") != _NON_AUTHORITIES
            or type(value.get("captured")) is not bool
        ):
            raise PwnRuntimeSnapshotGateEvaluationError(
                "invalid_gate_schema"
            )
        semantic_value = value.get("semantic_result")
        transport_value = value.get("transport_error")
        if (semantic_value is None) == (transport_value is None):
            raise PwnRuntimeSnapshotGateEvaluationError(
                "invalid_gate_branch"
            )
        if semantic_value is not None:
            if type(semantic_value) is not dict:
                raise PwnRuntimeSnapshotGateEvaluationError(
                    "invalid_gate_semantic_result"
                )
            try:
                semantic = parse_pwn_runtime_snapshot_v1_result(
                    _canonical_json_bytes(semantic_value),
                    **_semantic_bindings(recipe),
                )
            except PwnRuntimeSnapshotV1ContractError as error:
                raise PwnRuntimeSnapshotGateEvaluationError(
                    "invalid_gate_semantic_result"
                ) from error
            transport = None
        else:
            semantic = None
            transport = PwnRuntimeSnapshotTransportError.from_dict(
                transport_value
            )
        try:
            result = cls(
                status=PwnRuntimeSnapshotV1Status(value["status"]),
                reason_code=value["reason_code"],
                semantic_result=semantic,
                transport_error=transport,
            )
        except (KeyError, TypeError, ValueError) as error:
            raise PwnRuntimeSnapshotGateEvaluationError(
                "invalid_gate_schema"
            ) from error
        if value != result.to_dict():
            raise PwnRuntimeSnapshotGateEvaluationError(
                "gate_not_reconstructable"
            )
        result.canonical_bytes()
        return result


def _semantic_bindings(
    recipe: PwnRuntimeSnapshotRecipe,
) -> dict[str, object]:
    return {
        "expected_source_manifest_sha256": (
            recipe.source_manifest_sha256
        ),
        "expected_source_sha256": recipe.source_sha256,
        "expected_source_size_bytes": recipe.source_size_bytes,
        "expected_payload_sha256": recipe.payload_sha256,
        "expected_payload_size_bytes": recipe.payload_size_bytes,
        "expected_parent_crash_recipe_sha256": (
            recipe.parent_crash_recipe_sha256
        ),
        "expected_parent_crash_evaluation_sha256": (
            recipe.parent_crash_evaluation_sha256
        ),
        "expected_signal_number": recipe.expected_signal_number,
        "expected_snapshot_recipe_sha256": recipe.recipe_sha256,
    }


def _transport_evaluation(
    code: str,
    *,
    contract_code: str | None = None,
) -> PwnRuntimeSnapshotGateEvaluation:
    error = PwnRuntimeSnapshotTransportError(
        code=code,
        contract_code=contract_code,
    )
    return PwnRuntimeSnapshotGateEvaluation(
        status=PwnRuntimeSnapshotV1Status.ERROR,
        reason_code=f"transport_{code}",
        semantic_result=None,
        transport_error=error,
    )


def evaluate_pwn_runtime_snapshot_gate(
    recipe: PwnRuntimeSnapshotRecipe,
    *,
    stdout_payload: bytes,
    receipt: (
        PwnRuntimeSnapshotReceiptMetadata
        | Mapping[str, object]
    ),
) -> PwnRuntimeSnapshotGateEvaluation:
    """Strictly evaluate one producer document and its durable transport."""

    if type(recipe) is not PwnRuntimeSnapshotRecipe:
        raise TypeError("recipe must be an exact snapshot recipe")
    try:
        metadata = (
            receipt
            if type(receipt) is PwnRuntimeSnapshotReceiptMetadata
            else PwnRuntimeSnapshotReceiptMetadata.from_dict(receipt)
        )
    except (TypeError, ValueError):
        return _transport_evaluation("invalid_receipt_metadata")
    assert type(metadata) is PwnRuntimeSnapshotReceiptMetadata
    if (
        metadata.configuration_epoch != recipe.configuration_epoch
        or metadata.image_digest != recipe.image_digest
        or metadata.recipe_sha256 != recipe.recipe_sha256
        or metadata.producer_capability_name
        != PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME
        or metadata.producer_file_sha256
        != recipe.producer_file_sha256
        or metadata.sandbox_method
        != PWN_RUNTIME_SNAPSHOT_SANDBOX_METHOD
        or metadata.network != PWN_RUNTIME_SNAPSHOT_NETWORK_POLICY
        or metadata.one_shot is not PWN_RUNTIME_SNAPSHOT_ONE_SHOT
    ):
        return _transport_evaluation("receipt_binding_mismatch")
    if (
        metadata.outcome != "succeeded"
        or metadata.exit_code != 0
        or metadata.timed_out
        or metadata.orchestration_error is not None
    ):
        return _transport_evaluation("producer_transport_failed")
    if (
        type(stdout_payload) is not bytes
        or metadata.stdout_artifact_id is None
        or metadata.stdout_artifact_sha256 is None
        or metadata.stdout_artifact_size_bytes is None
        or not metadata.clean_workspace
        or not metadata.durable_stdout_artifact_complete
    ):
        return _transport_evaluation("stdout_artifact_incomplete")
    if (
        not metadata.stdout_capture_complete
        or not metadata.stdout_truncation_known
        or metadata.stdout_truncated is not False
        or metadata.stdout_error is not None
        or metadata.stream_capture_error is not None
    ):
        return _transport_evaluation("stdout_capture_incomplete")
    if (
        len(stdout_payload) > PWN_RUNTIME_SNAPSHOT_V1_MAX_DOCUMENT_BYTES
        or len(stdout_payload)
        != metadata.stdout_artifact_size_bytes
        or len(stdout_payload) != metadata.stdout_drained_bytes
        or len(stdout_payload) != metadata.stdout_stored_bytes
    ):
        return _transport_evaluation("stdout_size_binding_mismatch")
    if (
        hashlib.sha256(stdout_payload).hexdigest()
        != metadata.stdout_artifact_sha256
    ):
        return _transport_evaluation("stdout_hash_binding_mismatch")
    try:
        semantic = parse_pwn_runtime_snapshot_v1_result(
            stdout_payload,
            **_semantic_bindings(recipe),
        )
    except PwnRuntimeSnapshotV1ContractError as error:
        return _transport_evaluation(
            "producer_document_rejected",
            contract_code=error.code,
        )
    return PwnRuntimeSnapshotGateEvaluation(
        status=semantic.status,
        reason_code=semantic.reason_code,
        semantic_result=semantic,
        transport_error=None,
    )


__all__ = [
    "PWN_RUNTIME_SNAPSHOT_ARGV_TEMPLATE",
    "PWN_RUNTIME_SNAPSHOT_CAPABILITY_PROBE_CONTRACT",
    "PWN_RUNTIME_SNAPSHOT_INPUT_ARGUMENT",
    "PWN_RUNTIME_SNAPSHOT_INPUT_DESTINATION_LOCATOR",
    "PWN_RUNTIME_SNAPSHOT_NETWORK_POLICY",
    "PWN_RUNTIME_SNAPSHOT_ONE_SHOT",
    "PWN_RUNTIME_SNAPSHOT_PRODUCER_CAPABILITY_NAME",
    "PWN_RUNTIME_SNAPSHOT_PRODUCER_FILE_SHA256",
    "PWN_RUNTIME_SNAPSHOT_PRODUCER_INTERPRETER_PATH",
    "PWN_RUNTIME_SNAPSHOT_PRODUCER_PATH",
    "PWN_RUNTIME_SNAPSHOT_SANDBOX_METHOD",
    "PwnRuntimeSnapshotCapabilityAttestation",
    "PwnRuntimeSnapshotCapabilityAttestationError",
    "PwnRuntimeSnapshotGateEvaluation",
    "PwnRuntimeSnapshotGateEvaluationError",
    "PwnRuntimeSnapshotReceiptMetadata",
    "PwnRuntimeSnapshotRecipe",
    "PwnRuntimeSnapshotRecipeError",
    "PwnRuntimeSnapshotTransportError",
    "evaluate_pwn_runtime_snapshot_gate",
    "normalize_pwn_runtime_snapshot_capability_attestation",
    "pwn_runtime_snapshot_child_experiment_id",
]
