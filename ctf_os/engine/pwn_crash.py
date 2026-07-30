"""Engine-owned recipe and transport evidence for the Pwn crash v1 gate.

The model may nominate one canonical payload artifact.  It does not control
the command, target, arguments, fault signal, verdict, network policy, image,
or repetition plan.  This module binds those engine-owned choices into one
canonical, hash-addressed recipe before any execution starts.

Each attempt must run in a distinct one-shot ``run_clean_proof`` sandbox.
Only six complete, non-truncated, durable stdout artifacts from successful
producer invocations are delegated to the semantic
``ctf_os.contracts.pwn_crash_v1`` evaluator.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from itertools import islice
from pathlib import PurePosixPath
from typing import Any

from ctf_os.capabilities import REQUIRED_MANAGED_ATTESTATIONS
from ctf_os.contracts.pwn_crash_v1 import (
    PWN_CRASH_V1_ATTEMPT_COUNT,
    PWN_CRASH_V1_CONTRACT_FINGERPRINT,
    PWN_CRASH_V1_CONTRACT_ID,
    PWN_CRASH_V1_CONTRACT_VERSION,
    PWN_CRASH_V1_CONTROL_ATTEMPTS,
    PWN_CRASH_V1_DOCUMENT_TRANSPORT,
    PWN_CRASH_V1_MAX_DOCUMENT_BYTES,
    PWN_CRASH_V1_MAX_INPUT_BYTES,
    PWN_CRASH_V1_MAX_SOURCE_BYTES,
    PWN_CRASH_V1_POSITIVE_ATTEMPTS,
    PWN_CRASH_V1_PROTOCOL,
    PWN_CRASH_V1_TARGET_TIMEOUT_SECONDS,
    PwnCrashV1Evaluation,
    evaluate_pwn_crash_v1,
    pwn_crash_v1_contract_descriptor,
)


PWN_CRASH_RECIPE_SCHEMA_VERSION = 1
PWN_CRASH_PRODUCER_CAPABILITY_NAME = "pwn_crash_v1"
PWN_CRASH_PRODUCER_INTERPRETER_PATH = "/usr/bin/python3"
PWN_CRASH_PRODUCER_PATH = "/opt/ctf-templates/pwn/crash_oracle.py"
PWN_CRASH_PRODUCER_FILE_SHA256 = str(
    REQUIRED_MANAGED_ATTESTATIONS[
        PWN_CRASH_PRODUCER_CAPABILITY_NAME
    ]["sha256"]
)
PWN_CRASH_SANDBOX_METHOD = "run_clean_proof"
PWN_CRASH_NETWORK_POLICY = "none"
PWN_CRASH_INPUT_DESTINATION_LOCATOR = "pwn-crash-v1/input.bin"
PWN_CRASH_INPUT_ARGUMENT = f"/work/{PWN_CRASH_INPUT_DESTINATION_LOCATOR}"
PWN_CRASH_ONE_SHOT = True
PWN_CRASH_MAX_RECIPE_BYTES = 64 * 1024
PWN_CRASH_MAX_IDENTIFIER_BYTES = 512
PWN_CRASH_MAX_LOCATOR_BYTES = 4096
PWN_CRASH_MAX_IMAGE_REFERENCE_BYTES = 512
PWN_CRASH_MAX_JSON_DEPTH = 16
PWN_CRASH_MAX_JSON_NODES = 2048

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,511}$")
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_RECIPE_TOP_LEVEL_KEYS = frozenset(
    {
        "configuration_epoch",
        "contract",
        "experiment_id",
        "hypothesis_id",
        "payload",
        "protocol",
        "recipe_sha256",
        "runtime",
        "schema_version",
        "source",
    }
)
_RECIPE_CONTRACT_KEYS = frozenset({"fingerprint", "id", "version"})
_RECIPE_SOURCE_KEYS = frozenset(
    {"kind", "locator", "manifest_sha256", "sha256", "size_bytes"}
)
_RECIPE_PAYLOAD_KEYS = frozenset(
    {
        "artifact_id",
        "kind",
        "locator",
        "sha256",
        "size_bytes",
        "source_run_id",
    }
)
_RECIPE_RUNTIME_KEYS = frozenset(
    {
        "attempt_plan",
        "control_attempts",
        "document_transport",
        "execution_profile",
        "image",
        "network",
        "one_shot",
        "positive_attempts",
        "producer",
        "sandbox_method",
        "target_timeout_seconds",
    }
)
_RECIPE_IMAGE_KEYS = frozenset({"digest", "reference"})
_RECIPE_PRODUCER_KEYS = frozenset(
    {"capability_name", "file_sha256", "interpreter_path", "path"}
)
_RECEIPT_KEYS = frozenset(
    {
        "clean_workspace",
        "configuration_epoch",
        "durable_stdout_artifact_complete",
        "exit_code",
        "image_digest",
        "network",
        "one_shot",
        "ordinal",
        "orchestration_error",
        "outcome",
        "producer_capability_name",
        "producer_file_sha256",
        "receipt_id",
        "recipe_sha256",
        "run_id",
        "sandbox_method",
        "stdout_artifact_id",
        "stdout_artifact_sha256",
        "stdout_artifact_size_bytes",
        "stdout_capture_complete",
        "stdout_drained_bytes",
        "stdout_error",
        "stdout_stored_bytes",
        "stdout_truncated",
        "stdout_truncation_known",
        "stream_capture_error",
        "timed_out",
    }
)
_RECEIPT_OUTCOMES = frozenset(
    {"succeeded", "failed", "timed_out", "cancelled", "interrupted"}
)


class PwnCrashRecipeError(ValueError):
    """A recipe is malformed, stale, or has a mismatched content hash."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class PwnCrashTransportError(ValueError):
    """Execution transport failed before semantic crash classification."""

    def __init__(self, code: str, *, ordinal: int | None = None) -> None:
        super().__init__(
            code if ordinal is None else f"{code}: attempt {ordinal}"
        )
        self.code = code
        self.ordinal = ordinal


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


def _validate_json_tree(value: object) -> None:
    """Bound an untrusted decoded recipe before canonical serialization."""

    pending: list[tuple[Iterable[object], int]] = [
        (iter((value,)), 1)
    ]
    nodes = 0
    maximum_encoded_bytes = 0
    while pending:
        iterator, depth = pending[-1]
        try:
            current = next(iterator)
        except StopIteration:
            pending.pop()
            continue
        nodes += 1
        if depth > PWN_CRASH_MAX_JSON_DEPTH:
            raise PwnCrashRecipeError("recipe_depth_exceeded")
        if nodes > PWN_CRASH_MAX_JSON_NODES:
            raise PwnCrashRecipeError("recipe_node_limit_exceeded")
        if type(current) is dict:
            values: list[object] = []
            for key, item in current.items():
                if type(key) is not str:
                    raise PwnCrashRecipeError("invalid_recipe_schema")
                if len(key) > PWN_CRASH_MAX_RECIPE_BYTES:
                    raise PwnCrashRecipeError("recipe_size_exceeded")
                maximum_encoded_bytes += (12 * len(key)) + 4
                if maximum_encoded_bytes > PWN_CRASH_MAX_RECIPE_BYTES:
                    raise PwnCrashRecipeError("recipe_size_exceeded")
                values.append(item)
                if len(values) > PWN_CRASH_MAX_JSON_NODES:
                    raise PwnCrashRecipeError(
                        "recipe_node_limit_exceeded"
                    )
            pending.append((iter(values), depth + 1))
        elif type(current) is list:
            pending.append((iter(current), depth + 1))
        elif type(current) is str:
            if len(current) > PWN_CRASH_MAX_RECIPE_BYTES:
                raise PwnCrashRecipeError("recipe_size_exceeded")
            maximum_encoded_bytes += (12 * len(current)) + 2
        elif type(current) is int:
            if current.bit_length() > PWN_CRASH_MAX_RECIPE_BYTES:
                raise PwnCrashRecipeError("recipe_size_exceeded")
            maximum_encoded_bytes += max(1, current.bit_length()) + 2
        elif type(current) in {bool, type(None)}:
            maximum_encoded_bytes += 5
        elif type(current) is float and math.isfinite(current):
            maximum_encoded_bytes += 32
        else:
            raise PwnCrashRecipeError("invalid_recipe_schema")
        if maximum_encoded_bytes > PWN_CRASH_MAX_RECIPE_BYTES:
            raise PwnCrashRecipeError("recipe_size_exceeded")


def _exact_dict(
    value: object,
    keys: frozenset[str],
) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise PwnCrashRecipeError("invalid_recipe_schema")
    return value


def _require_sha256(value: object, label: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise PwnCrashRecipeError(f"invalid_{label}")
    return value


def _require_identifier(value: object, label: str) -> str:
    if type(value) is not str:
        raise PwnCrashRecipeError(f"invalid_{label}")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise PwnCrashRecipeError(f"invalid_{label}") from error
    if (
        len(encoded) > PWN_CRASH_MAX_IDENTIFIER_BYTES
        or _IDENTIFIER.fullmatch(value) is None
    ):
        raise PwnCrashRecipeError(f"invalid_{label}")
    return value


def _require_locator(value: object, label: str) -> str:
    if type(value) is not str:
        raise PwnCrashRecipeError(f"invalid_{label}")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise PwnCrashRecipeError(f"invalid_{label}") from error
    if (
        not value
        or len(encoded) > PWN_CRASH_MAX_LOCATOR_BYTES
        or value.startswith("/")
        or value.endswith("/")
        or "\\" in value
        or "\x00" in value
        or "//" in value
        or any(
            unicodedata.category(character).startswith("C")
            for character in value
        )
    ):
        raise PwnCrashRecipeError(f"invalid_{label}")
    parts = value.split("/")
    if any(
        part in {"", ".", ".."}
        or len(part.encode("utf-8")) > 255
        for part in parts
    ):
        raise PwnCrashRecipeError(f"invalid_{label}")
    if PurePosixPath(value).as_posix() != value:
        raise PwnCrashRecipeError(f"invalid_{label}")
    return value


def _require_size(
    value: object,
    label: str,
    *,
    maximum: int,
    nonempty: bool,
) -> int:
    minimum = 1 if nonempty else 0
    if type(value) is not int or not minimum <= value <= maximum:
        raise PwnCrashRecipeError(f"invalid_{label}")
    return value


def _require_image_reference(value: object) -> str:
    if type(value) is not str:
        raise PwnCrashRecipeError("invalid_image_reference")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise PwnCrashRecipeError("invalid_image_reference") from error
    if (
        not value
        or value != value.strip()
        or len(encoded) > PWN_CRASH_MAX_IMAGE_REFERENCE_BYTES
        or "\x00" in value
        or any(
            character.isspace()
            or unicodedata.category(character).startswith("C")
            for character in value
        )
    ):
        raise PwnCrashRecipeError("invalid_image_reference")
    return value


def _require_image_digest(value: object) -> str:
    if type(value) is not str or _IMAGE_DIGEST.fullmatch(value) is None:
        raise PwnCrashRecipeError("invalid_image_digest")
    return value


def _attempt_plan(
    payload_sha256: str,
    payload_size_bytes: int,
) -> list[dict[str, object]]:
    return [
        {
            "input_kind": (
                "canonical_payload_artifact"
                if ordinal <= PWN_CRASH_V1_POSITIVE_ATTEMPTS
                else "empty_control"
            ),
            "input_sha256": (
                payload_sha256
                if ordinal <= PWN_CRASH_V1_POSITIVE_ATTEMPTS
                else _EMPTY_SHA256
            ),
            "input_size_bytes": (
                payload_size_bytes
                if ordinal <= PWN_CRASH_V1_POSITIVE_ATTEMPTS
                else 0
            ),
            "ordinal": ordinal,
            "phase": (
                "positive"
                if ordinal <= PWN_CRASH_V1_POSITIVE_ATTEMPTS
                else "control"
            ),
        }
        for ordinal in range(1, PWN_CRASH_V1_ATTEMPT_COUNT + 1)
    ]


def _execution_profile() -> dict[str, object]:
    descriptor = pwn_crash_v1_contract_descriptor()
    profile = descriptor.get("execution_profile")
    if type(profile) is not dict:
        raise AssertionError("Pwn crash v1 contract lacks execution profile")
    return profile


@dataclass(frozen=True, slots=True)
class PwnCrashRecipe:
    """Dynamic engine bindings for the otherwise fixed Pwn crash recipe."""

    configuration_epoch: int
    experiment_id: str
    hypothesis_id: str
    primary_elf_locator: str
    source_manifest_sha256: str
    source_sha256: str
    source_size_bytes: int
    payload_artifact_id: str
    payload_source_run_id: str
    payload_artifact_locator: str
    payload_sha256: str
    payload_size_bytes: int
    image_reference: str
    image_digest: str
    producer_file_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.configuration_epoch) is not int
            or not 0 <= self.configuration_epoch <= (2**63 - 1)
        ):
            raise PwnCrashRecipeError("invalid_configuration_epoch")
        _require_identifier(self.experiment_id, "experiment_id")
        _require_identifier(self.hypothesis_id, "hypothesis_id")
        _require_locator(
            self.primary_elf_locator,
            "primary_elf_locator",
        )
        _require_sha256(
            self.source_manifest_sha256,
            "source_manifest_sha256",
        )
        _require_sha256(self.source_sha256, "source_sha256")
        _require_size(
            self.source_size_bytes,
            "source_size_bytes",
            maximum=PWN_CRASH_V1_MAX_SOURCE_BYTES,
            nonempty=True,
        )
        _require_identifier(
            self.payload_artifact_id,
            "payload_artifact_id",
        )
        _require_identifier(
            self.payload_source_run_id,
            "payload_source_run_id",
        )
        _require_locator(
            self.payload_artifact_locator,
            "payload_artifact_locator",
        )
        _require_sha256(self.payload_sha256, "payload_sha256")
        _require_size(
            self.payload_size_bytes,
            "payload_size_bytes",
            maximum=PWN_CRASH_V1_MAX_INPUT_BYTES,
            nonempty=True,
        )
        _require_image_reference(self.image_reference)
        _require_image_digest(self.image_digest)
        _require_sha256(
            self.producer_file_sha256,
            "producer_file_sha256",
        )
        if self.producer_file_sha256 != PWN_CRASH_PRODUCER_FILE_SHA256:
            raise PwnCrashRecipeError(
                "producer_attestation_mismatch"
            )

    def content_dict(self) -> dict[str, object]:
        """Return canonical recipe content, excluding its derived hash."""

        return {
            "configuration_epoch": self.configuration_epoch,
            "contract": {
                "fingerprint": PWN_CRASH_V1_CONTRACT_FINGERPRINT,
                "id": PWN_CRASH_V1_CONTRACT_ID,
                "version": PWN_CRASH_V1_CONTRACT_VERSION,
            },
            "experiment_id": self.experiment_id,
            "hypothesis_id": self.hypothesis_id,
            "payload": {
                "artifact_id": self.payload_artifact_id,
                "kind": "canonical_artifact",
                "locator": self.payload_artifact_locator,
                "sha256": self.payload_sha256,
                "size_bytes": self.payload_size_bytes,
                "source_run_id": self.payload_source_run_id,
            },
            "protocol": PWN_CRASH_V1_PROTOCOL,
            "runtime": {
                "attempt_plan": _attempt_plan(
                    self.payload_sha256,
                    self.payload_size_bytes,
                ),
                "control_attempts": PWN_CRASH_V1_CONTROL_ATTEMPTS,
                "document_transport": PWN_CRASH_V1_DOCUMENT_TRANSPORT,
                "execution_profile": _execution_profile(),
                "image": {
                    "digest": self.image_digest,
                    "reference": self.image_reference,
                },
                "network": PWN_CRASH_NETWORK_POLICY,
                "one_shot": PWN_CRASH_ONE_SHOT,
                "positive_attempts": PWN_CRASH_V1_POSITIVE_ATTEMPTS,
                "producer": {
                    "capability_name": (
                        PWN_CRASH_PRODUCER_CAPABILITY_NAME
                    ),
                    "file_sha256": self.producer_file_sha256,
                    "interpreter_path": (
                        PWN_CRASH_PRODUCER_INTERPRETER_PATH
                    ),
                    "path": PWN_CRASH_PRODUCER_PATH,
                },
                "sandbox_method": PWN_CRASH_SANDBOX_METHOD,
                "target_timeout_seconds": (
                    PWN_CRASH_V1_TARGET_TIMEOUT_SECONDS
                ),
            },
            "schema_version": PWN_CRASH_RECIPE_SCHEMA_VERSION,
            "source": {
                "kind": "immutable_primary_elf",
                "locator": self.primary_elf_locator,
                "manifest_sha256": self.source_manifest_sha256,
                "sha256": self.source_sha256,
                "size_bytes": self.source_size_bytes,
            },
        }

    @property
    def recipe_sha256(self) -> str:
        """Hash the exact canonical recipe content, excluding this field."""

        return hashlib.sha256(
            _canonical_json_bytes(self.content_dict())
        ).hexdigest()

    def to_dict(self) -> dict[str, object]:
        result = self.content_dict()
        result["recipe_sha256"] = self.recipe_sha256
        return result

    def canonical_bytes(self) -> bytes:
        payload = _canonical_json_bytes(self.to_dict())
        if len(payload) > PWN_CRASH_MAX_RECIPE_BYTES:
            raise PwnCrashRecipeError("recipe_size_exceeded")
        return payload

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "PwnCrashRecipe":
        """Parse an exact recipe and verify its self-hash and fixed fields."""

        if type(value) is not dict:
            raise PwnCrashRecipeError("invalid_recipe_schema")
        _validate_json_tree(value)
        try:
            encoded = _canonical_json_bytes(value)
        except (RecursionError, TypeError, ValueError) as error:
            raise PwnCrashRecipeError("invalid_recipe_schema") from error
        if len(encoded) > PWN_CRASH_MAX_RECIPE_BYTES:
            raise PwnCrashRecipeError("recipe_size_exceeded")

        root = _exact_dict(value, _RECIPE_TOP_LEVEL_KEYS)
        contract = _exact_dict(
            root.get("contract"),
            _RECIPE_CONTRACT_KEYS,
        )
        source = _exact_dict(root.get("source"), _RECIPE_SOURCE_KEYS)
        payload = _exact_dict(root.get("payload"), _RECIPE_PAYLOAD_KEYS)
        runtime = _exact_dict(root.get("runtime"), _RECIPE_RUNTIME_KEYS)
        image = _exact_dict(runtime.get("image"), _RECIPE_IMAGE_KEYS)
        producer = _exact_dict(
            runtime.get("producer"),
            _RECIPE_PRODUCER_KEYS,
        )

        supplied_hash = _require_sha256(
            root.get("recipe_sha256"),
            "recipe_sha256",
        )
        try:
            recipe = cls(
                configuration_epoch=root["configuration_epoch"],
                experiment_id=root["experiment_id"],
                hypothesis_id=root["hypothesis_id"],
                primary_elf_locator=source["locator"],
                source_manifest_sha256=source["manifest_sha256"],
                source_sha256=source["sha256"],
                source_size_bytes=source["size_bytes"],
                payload_artifact_id=payload["artifact_id"],
                payload_source_run_id=payload["source_run_id"],
                payload_artifact_locator=payload["locator"],
                payload_sha256=payload["sha256"],
                payload_size_bytes=payload["size_bytes"],
                image_reference=image["reference"],
                image_digest=image["digest"],
                producer_file_sha256=producer["file_sha256"],
            )
        except KeyError as error:
            raise PwnCrashRecipeError("invalid_recipe_schema") from error

        expected = recipe.to_dict()
        if supplied_hash != recipe.recipe_sha256:
            raise PwnCrashRecipeError("recipe_hash_mismatch")
        if _canonical_json_bytes(root) != _canonical_json_bytes(expected):
            # This covers every engine-owned constant, nested key, value type,
            # repetition count, attempt order, and execution-profile field.
            raise PwnCrashRecipeError("recipe_contract_mismatch")
        return recipe

    def validate_payload(self, payload: bytes) -> None:
        """Require the exact non-empty canonical artifact bytes."""

        if type(payload) is not bytes:
            raise PwnCrashRecipeError("invalid_payload_bytes")
        if (
            len(payload) != self.payload_size_bytes
            or hashlib.sha256(payload).hexdigest() != self.payload_sha256
        ):
            raise PwnCrashRecipeError("payload_binding_mismatch")

    def attempt_input_binding(self, ordinal: int) -> dict[str, object]:
        """Return the fixed input binding for one one-shot attempt."""

        if (
            type(ordinal) is not int
            or not 1 <= ordinal <= PWN_CRASH_V1_ATTEMPT_COUNT
        ):
            raise ValueError("ordinal must be an integer from 1 through 6")
        return dict(
            _attempt_plan(
                self.payload_sha256,
                self.payload_size_bytes,
            )[ordinal - 1]
        )

    def argv_for_attempt(self, ordinal: int) -> tuple[str, ...]:
        """Generate the only producer argv accepted for this recipe."""

        binding = self.attempt_input_binding(ordinal)
        return (
            PWN_CRASH_PRODUCER_INTERPRETER_PATH,
            PWN_CRASH_PRODUCER_PATH,
            "--binary",
            f"/challenge/{self.primary_elf_locator}",
            "--input",
            PWN_CRASH_INPUT_ARGUMENT,
            "--ordinal",
            str(binding["ordinal"]),
            "--phase",
            str(binding["phase"]),
            "--source-manifest-sha256",
            self.source_manifest_sha256,
            "--source-sha256",
            self.source_sha256,
            "--source-size-bytes",
            str(self.source_size_bytes),
            "--input-sha256",
            str(binding["input_sha256"]),
            "--input-size-bytes",
            str(binding["input_size_bytes"]),
            "--recipe-sha256",
            self.recipe_sha256,
        )


@dataclass(frozen=True, slots=True)
class PwnCrashReceiptMetadata:
    """Transport fields required for one durable producer observation."""

    ordinal: int
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
    producer_capability_name: str
    producer_file_sha256: str
    stdout_artifact_id: str | None
    stdout_artifact_sha256: str | None
    stdout_artifact_size_bytes: int | None
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
        if (
            type(self.ordinal) is not int
            or not 1 <= self.ordinal <= PWN_CRASH_V1_ATTEMPT_COUNT
        ):
            raise ValueError("ordinal must be an integer from 1 through 6")
        _receipt_identifier(self.receipt_id, "receipt_id")
        _receipt_identifier(self.run_id, "run_id")
        if type(self.outcome) is not str or self.outcome not in _RECEIPT_OUTCOMES:
            raise ValueError("invalid receipt outcome")
        if (
            self.exit_code is not None
            and (
                type(self.exit_code) is not int
                or not -255 <= self.exit_code <= 255
            )
        ):
            raise ValueError("invalid receipt exit_code")
        for name in (
            "timed_out",
            "clean_workspace",
            "one_shot",
            "stdout_capture_complete",
            "stdout_truncation_known",
            "durable_stdout_artifact_complete",
        ):
            if type(getattr(self, name)) is not bool:
                raise ValueError(f"invalid receipt {name}")
        if self.stdout_truncated is not None and type(
            self.stdout_truncated
        ) is not bool:
            raise ValueError("invalid receipt stdout_truncated")
        if type(self.configuration_epoch) is not int or (
            self.configuration_epoch < 0
            or self.configuration_epoch > (2**63 - 1)
        ):
            raise ValueError("invalid receipt configuration_epoch")
        _receipt_text(self.sandbox_method, "sandbox_method")
        _receipt_text(self.network, "network")
        if (
            type(self.image_digest) is not str
            or _IMAGE_DIGEST.fullmatch(self.image_digest) is None
        ):
            raise ValueError("invalid receipt image_digest")
        for name in ("recipe_sha256", "producer_file_sha256"):
            value = getattr(self, name)
            if type(value) is not str or _SHA256.fullmatch(value) is None:
                raise ValueError(f"invalid receipt {name}")
        _receipt_text(
            self.producer_capability_name,
            "producer_capability_name",
        )
        for name in ("stdout_artifact_id",):
            value = getattr(self, name)
            if value is not None:
                _receipt_identifier(value, name)
        if self.stdout_artifact_sha256 is not None and (
            type(self.stdout_artifact_sha256) is not str
            or _SHA256.fullmatch(self.stdout_artifact_sha256) is None
        ):
            raise ValueError("invalid receipt stdout_artifact_sha256")
        for name in (
            "stdout_artifact_size_bytes",
            "stdout_drained_bytes",
            "stdout_stored_bytes",
        ):
            value = getattr(self, name)
            if value is None and name == "stdout_artifact_size_bytes":
                continue
            if type(value) is not int or value < 0:
                raise ValueError(f"invalid receipt {name}")
        for name in (
            "stdout_error",
            "stream_capture_error",
            "orchestration_error",
        ):
            value = getattr(self, name)
            if value is not None:
                _receipt_text(value, name)

    def to_dict(self) -> dict[str, object]:
        return {
            "clean_workspace": self.clean_workspace,
            "configuration_epoch": self.configuration_epoch,
            "durable_stdout_artifact_complete": (
                self.durable_stdout_artifact_complete
            ),
            "exit_code": self.exit_code,
            "image_digest": self.image_digest,
            "network": self.network,
            "one_shot": self.one_shot,
            "ordinal": self.ordinal,
            "orchestration_error": self.orchestration_error,
            "outcome": self.outcome,
            "producer_capability_name": self.producer_capability_name,
            "producer_file_sha256": self.producer_file_sha256,
            "receipt_id": self.receipt_id,
            "recipe_sha256": self.recipe_sha256,
            "run_id": self.run_id,
            "sandbox_method": self.sandbox_method,
            "stdout_artifact_id": self.stdout_artifact_id,
            "stdout_artifact_sha256": self.stdout_artifact_sha256,
            "stdout_artifact_size_bytes": (
                self.stdout_artifact_size_bytes
            ),
            "stdout_capture_complete": self.stdout_capture_complete,
            "stdout_drained_bytes": self.stdout_drained_bytes,
            "stdout_error": self.stdout_error,
            "stdout_stored_bytes": self.stdout_stored_bytes,
            "stdout_truncated": self.stdout_truncated,
            "stdout_truncation_known": self.stdout_truncation_known,
            "stream_capture_error": self.stream_capture_error,
            "timed_out": self.timed_out,
        }

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
    ) -> "PwnCrashReceiptMetadata":
        if type(value) is not dict or set(value) != _RECEIPT_KEYS:
            raise ValueError("invalid receipt metadata schema")
        return cls(**value)


def _receipt_identifier(value: object, label: str) -> str:
    if type(value) is not str:
        raise ValueError(f"invalid receipt {label}")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"invalid receipt {label}") from error
    if (
        len(encoded) > PWN_CRASH_MAX_IDENTIFIER_BYTES
        or _IDENTIFIER.fullmatch(value) is None
    ):
        raise ValueError(f"invalid receipt {label}")
    return value


def _receipt_text(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"invalid receipt {label}")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"invalid receipt {label}") from error
    if (
        len(encoded) > PWN_CRASH_MAX_IDENTIFIER_BYTES
        or "\x00" in value
        or any(
            unicodedata.category(character).startswith("C")
            for character in value
        )
    ):
        raise ValueError(f"invalid receipt {label}")
    return value


def _bounded_tuple(
    values: Iterable[Any],
    *,
    expected: int,
    code: str,
) -> tuple[Any, ...]:
    try:
        iterator = iter(values)
        selected = tuple(islice(iterator, expected + 1))
    except Exception as error:
        raise PwnCrashTransportError(code) from error
    if len(selected) != expected:
        raise PwnCrashTransportError(code)
    return selected


def evaluate_pwn_crash_evidence(
    recipe: PwnCrashRecipe,
    *,
    poc_input: bytes,
    stdout_payloads: Iterable[bytes],
    receipts: Iterable[PwnCrashReceiptMetadata | Mapping[str, object]],
) -> PwnCrashV1Evaluation:
    """Validate transport evidence, then delegate only semantic classification."""

    if type(recipe) is not PwnCrashRecipe:
        raise TypeError("recipe must be a PwnCrashRecipe")
    try:
        recipe.validate_payload(poc_input)
    except PwnCrashRecipeError as error:
        raise PwnCrashTransportError("payload_binding_mismatch") from error

    payload_values = _bounded_tuple(
        stdout_payloads,
        expected=PWN_CRASH_V1_ATTEMPT_COUNT,
        code="stdout_attempt_count_mismatch",
    )
    receipt_values = _bounded_tuple(
        receipts,
        expected=PWN_CRASH_V1_ATTEMPT_COUNT,
        code="receipt_attempt_count_mismatch",
    )

    normalized_receipts: list[PwnCrashReceiptMetadata] = []
    for ordinal, raw in enumerate(receipt_values, start=1):
        try:
            receipt = (
                raw
                if type(raw) is PwnCrashReceiptMetadata
                else PwnCrashReceiptMetadata.from_dict(raw)
            )
        except (TypeError, ValueError) as error:
            raise PwnCrashTransportError(
                "invalid_receipt_metadata",
                ordinal=ordinal,
            ) from error
        normalized_receipts.append(receipt)

    run_ids: set[str] = set()
    receipt_ids: set[str] = set()
    artifact_ids: set[str] = set()
    for ordinal, (payload, receipt) in enumerate(
        zip(payload_values, normalized_receipts, strict=True),
        start=1,
    ):
        if type(payload) is not bytes:
            raise PwnCrashTransportError(
                "stdout_payload_type_invalid",
                ordinal=ordinal,
            )
        if len(payload) > PWN_CRASH_V1_MAX_DOCUMENT_BYTES:
            raise PwnCrashTransportError(
                "stdout_payload_too_large",
                ordinal=ordinal,
            )
        if receipt.ordinal != ordinal:
            raise PwnCrashTransportError(
                "attempt_order_mismatch",
                ordinal=ordinal,
            )
        if receipt.run_id in run_ids:
            raise PwnCrashTransportError(
                "duplicate_run_id",
                ordinal=ordinal,
            )
        if receipt.receipt_id in receipt_ids:
            raise PwnCrashTransportError(
                "duplicate_receipt_id",
                ordinal=ordinal,
            )
        run_ids.add(receipt.run_id)
        receipt_ids.add(receipt.receipt_id)

        if receipt.outcome != "succeeded" or receipt.exit_code != 0:
            raise PwnCrashTransportError(
                "producer_execution_unsuccessful",
                ordinal=ordinal,
            )
        if receipt.timed_out:
            raise PwnCrashTransportError(
                "producer_execution_timed_out",
                ordinal=ordinal,
            )
        if not receipt.clean_workspace:
            raise PwnCrashTransportError(
                "clean_workspace_required",
                ordinal=ordinal,
            )
        if (
            receipt.one_shot is not PWN_CRASH_ONE_SHOT
            or receipt.sandbox_method != PWN_CRASH_SANDBOX_METHOD
        ):
            raise PwnCrashTransportError(
                "one_shot_sandbox_mismatch",
                ordinal=ordinal,
            )
        if receipt.network != PWN_CRASH_NETWORK_POLICY:
            raise PwnCrashTransportError(
                "network_policy_mismatch",
                ordinal=ordinal,
            )
        if receipt.configuration_epoch != recipe.configuration_epoch:
            raise PwnCrashTransportError(
                "configuration_epoch_mismatch",
                ordinal=ordinal,
            )
        if receipt.image_digest != recipe.image_digest:
            raise PwnCrashTransportError(
                "image_binding_mismatch",
                ordinal=ordinal,
            )
        if receipt.recipe_sha256 != recipe.recipe_sha256:
            raise PwnCrashTransportError(
                "recipe_binding_mismatch",
                ordinal=ordinal,
            )
        if (
            receipt.producer_capability_name
            != PWN_CRASH_PRODUCER_CAPABILITY_NAME
            or receipt.producer_file_sha256
            != recipe.producer_file_sha256
        ):
            raise PwnCrashTransportError(
                "producer_binding_mismatch",
                ordinal=ordinal,
            )
        if receipt.stdout_error is not None:
            raise PwnCrashTransportError(
                "stdout_capture_error",
                ordinal=ordinal,
            )
        if (
            receipt.stream_capture_error is not None
            or receipt.orchestration_error is not None
        ):
            raise PwnCrashTransportError(
                "transport_error",
                ordinal=ordinal,
            )
        if not receipt.stdout_capture_complete:
            raise PwnCrashTransportError(
                "stdout_capture_incomplete",
                ordinal=ordinal,
            )
        if not receipt.stdout_truncation_known:
            raise PwnCrashTransportError(
                "stdout_truncation_unknown",
                ordinal=ordinal,
            )
        if receipt.stdout_truncated is not False:
            raise PwnCrashTransportError(
                "stdout_capture_truncated",
                ordinal=ordinal,
            )
        if not receipt.durable_stdout_artifact_complete:
            raise PwnCrashTransportError(
                "durable_stdout_artifact_incomplete",
                ordinal=ordinal,
            )
        if (
            receipt.stdout_artifact_id is None
            or receipt.stdout_artifact_sha256 is None
            or receipt.stdout_artifact_size_bytes is None
        ):
            raise PwnCrashTransportError(
                "stdout_artifact_binding_incomplete",
                ordinal=ordinal,
            )
        if receipt.stdout_artifact_id in artifact_ids:
            raise PwnCrashTransportError(
                "duplicate_stdout_artifact_id",
                ordinal=ordinal,
            )
        artifact_ids.add(receipt.stdout_artifact_id)

        payload_size = len(payload)
        if (
            receipt.stdout_drained_bytes != payload_size
            or receipt.stdout_stored_bytes != payload_size
            or receipt.stdout_artifact_size_bytes != payload_size
        ):
            raise PwnCrashTransportError(
                "stdout_size_binding_mismatch",
                ordinal=ordinal,
            )
        if (
            hashlib.sha256(payload).hexdigest()
            != receipt.stdout_artifact_sha256
        ):
            raise PwnCrashTransportError(
                "stdout_hash_binding_mismatch",
                ordinal=ordinal,
            )

    return evaluate_pwn_crash_v1(
        payload_values,
        poc_input=poc_input,
        expected_source_manifest_sha256=(
            recipe.source_manifest_sha256
        ),
        expected_source_sha256=recipe.source_sha256,
        expected_source_size_bytes=recipe.source_size_bytes,
        expected_recipe_sha256=recipe.recipe_sha256,
    )


__all__ = [
    "PWN_CRASH_INPUT_ARGUMENT",
    "PWN_CRASH_INPUT_DESTINATION_LOCATOR",
    "PWN_CRASH_NETWORK_POLICY",
    "PWN_CRASH_ONE_SHOT",
    "PWN_CRASH_PRODUCER_CAPABILITY_NAME",
    "PWN_CRASH_PRODUCER_FILE_SHA256",
    "PWN_CRASH_PRODUCER_INTERPRETER_PATH",
    "PWN_CRASH_PRODUCER_PATH",
    "PWN_CRASH_RECIPE_SCHEMA_VERSION",
    "PWN_CRASH_SANDBOX_METHOD",
    "PwnCrashReceiptMetadata",
    "PwnCrashRecipe",
    "PwnCrashRecipeError",
    "PwnCrashTransportError",
    "evaluate_pwn_crash_evidence",
]
