"""Pure V1 contract for local Crypto/Misc data transcript recipes.

The model-visible recipe is data, not a program: it can only send exact bytes
and expect exact bytes from one stream.  An operator privately pre-issues the
peer executable and its seed data before a Builder run.  The public recipe
binds only the preissue identity and reset commitment; it cannot select a
command, interpreter, path, environment variable, or network target.

Execution and evidence validation live outside this module.  In particular,
the pinned producer owns the three clean replays, the three deterministic
negative controls, fresh-state reset, process cleanup, and raw artifacts.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Mapping

from ctf_os.contracts.interaction_data_common import (
    InteractionDataCommonError,
    canonical_ascii_json_bytes,
    parse_canonical_ascii_json,
)


DATA_TRANSCRIPT_V1_SCHEMA_VERSION = 1
DATA_TRANSCRIPT_V1_CONTRACT_ID = "ctfos.data_transcript.recipe"
DATA_TRANSCRIPT_V1_CONTRACT_VERSION = 1
DATA_TRANSCRIPT_V1_PROTOCOL = "crypto_misc_local_data_transcript_v1"
DATA_TRANSCRIPT_V1_PREISSUE_CONTRACT_ID = (
    "ctfos.data_transcript.oracle_preissue"
)
DATA_TRANSCRIPT_V1_PREISSUE_PROTOCOL = (
    "crypto_misc_local_data_transcript_preissue_v1"
)
DATA_TRANSCRIPT_V1_MAX_DOCUMENT_BYTES = 64 * 1024
DATA_TRANSCRIPT_V1_MAX_PREISSUE_BYTES = 64 * 1024
DATA_TRANSCRIPT_V1_MAX_JSON_DEPTH = 10
DATA_TRANSCRIPT_V1_MAX_STEPS = 64
DATA_TRANSCRIPT_V1_MAX_STEP_BYTES = 64 * 1024
DATA_TRANSCRIPT_V1_MAX_AGGREGATE_SEND_BYTES = 1024 * 1024
DATA_TRANSCRIPT_V1_MAX_AGGREGATE_EXPECT_BYTES = 1024 * 1024
DATA_TRANSCRIPT_V1_MAX_TIMEOUT_MILLISECONDS = 120_000
DATA_TRANSCRIPT_V1_MAX_PEER_BYTES = 1024 * 1024 * 1024
DATA_TRANSCRIPT_V1_MAX_PEER_DATA_BYTES = 1024 * 1024 * 1024
DATA_TRANSCRIPT_V1_CATEGORIES = frozenset({"crypto", "misc"})
DATA_TRANSCRIPT_V1_CONTROL_MUTATION = (
    "first_send_byte_xor_ordinal_bit_v1"
)
DATA_TRANSCRIPT_V1_RESET_MODE = "fresh_seed_copy_per_replay_v1"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SAFE_STEP_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_SAFE_HEX = re.compile(r"^(?:[0-9a-f]{2})*$")
_RECIPE_KEYS = frozenset(
    {
        "category",
        "contract",
        "preissue_id",
        "reset_commitment_sha256",
        "schema_version",
        "steps",
        "timeout_milliseconds",
    }
)
_CONTRACT_KEYS = frozenset({"id", "protocol", "version"})
_SEND_KEYS = frozenset({"data", "id", "op"})
_EXPECT_KEYS = frozenset(
    {"data", "id", "max_read_bytes", "op", "stream"}
)
_LITERAL_KEYS = frozenset({"encoding", "value"})
_PREISSUE_KEYS = frozenset(
    {
        "category",
        "configuration_epoch",
        "contract",
        "image_digest",
        "issue_revision",
        "issued_at",
        "peer",
        "peer_data",
        "preissue_id",
        "reset",
        "schema_version",
        "seal_nonce",
        "source_manifest_sha256",
    }
)
_PRIVATE_INPUT_KEYS = frozenset({"sha256", "size_bytes"})
_RESET_KEYS = frozenset(
    {
        "commitment_sha256",
        "control_mutation",
        "execution",
        "mode",
        "network",
    }
)


class DataTranscriptContractError(ValueError):
    """Stable fail-closed contract error."""

    def __init__(self, code: str, detail: str = "") -> None:
        message = code if not detail else f"{code}: {detail}"
        super().__init__(message)
        self.code = code
        self.detail = detail


@dataclass(frozen=True, slots=True)
class DataTranscriptRecipe:
    """Validated canonical Builder-authored transcript data."""

    category: str
    preissue_id: str
    reset_commitment_sha256: str
    document: Mapping[str, object]
    canonical_bytes: bytes
    sha256: str
    step_count: int
    aggregate_send_bytes: int
    aggregate_expect_bytes: int
    first_send_step_id: str


@dataclass(frozen=True, slots=True)
class DataTranscriptPreissueManifest:
    """Validated private operator preissue; never model-visible."""

    category: str
    preissue_id: str
    issue_revision: int
    issued_at: str
    configuration_epoch: int
    source_manifest_sha256: str
    image_digest: str
    peer_sha256: str
    peer_size_bytes: int
    peer_data_sha256: str
    peer_data_size_bytes: int
    reset_commitment_sha256: str
    seal_nonce: str
    document: Mapping[str, object]
    canonical_bytes: bytes
    sha256: str

    def public_record(self) -> dict[str, object]:
        """Return the only Builder-safe projection."""

        return {
            "category": self.category,
            "configuration_epoch": self.configuration_epoch,
            "image_digest": self.image_digest,
            "issue_revision": self.issue_revision,
            "issued_at": self.issued_at,
            "oracle_seal_sha256": self.sha256,
            "preissue_id": self.preissue_id,
            "protocol": DATA_TRANSCRIPT_V1_PREISSUE_PROTOCOL,
            "reset_commitment_sha256": self.reset_commitment_sha256,
            "schema_version": DATA_TRANSCRIPT_V1_SCHEMA_VERSION,
            "source_manifest_sha256": self.source_manifest_sha256,
            "status": "unused",
        }


def _fail(code: str, detail: str = "") -> None:
    raise DataTranscriptContractError(code, detail)


def _mapping(
    value: object,
    keys: frozenset[str],
    *,
    code: str = "invalid_schema",
) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != keys:
        _fail(code)
    return value


def _integer(
    value: object,
    minimum: int,
    maximum: int,
    *,
    code: str = "invalid_schema",
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(code)
    return value


def _sha256(value: object, *, code: str = "invalid_schema") -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        _fail(code)
    return value


def _safe_id(value: object, *, code: str = "invalid_schema") -> str:
    if type(value) is not str or _SAFE_ID.fullmatch(value) is None:
        _fail(code)
    return value


def _literal_bytes(value: object) -> bytes:
    raw = _mapping(value, _LITERAL_KEYS)
    encoding = raw["encoding"]
    encoded = raw["value"]
    if type(encoded) is not str or encoding not in {"hex", "utf8"}:
        _fail("invalid_literal")
    try:
        if encoding == "hex":
            if _SAFE_HEX.fullmatch(encoded) is None:
                _fail("invalid_literal")
            result = bytes.fromhex(encoded)
        else:
            result = encoded.encode("utf-8")
    except (UnicodeError, ValueError) as error:
        raise DataTranscriptContractError("invalid_literal") from error
    if not result or len(result) > DATA_TRANSCRIPT_V1_MAX_STEP_BYTES:
        _fail("step_byte_limit")
    return result


def data_transcript_v1_canonical_json_bytes(value: object) -> bytes:
    try:
        return canonical_ascii_json_bytes(value)
    except InteractionDataCommonError as error:
        raise DataTranscriptContractError(
            "invalid_json_value"
        ) from error


def data_transcript_v1_reset_descriptor(
    *,
    category: str,
    peer_sha256: str,
    peer_size_bytes: int,
    peer_data_sha256: str,
    peer_data_size_bytes: int,
) -> dict[str, object]:
    """Build the immutable reset semantics committed by a preissue."""

    if category not in DATA_TRANSCRIPT_V1_CATEGORIES:
        _fail("invalid_category")
    peer_digest = _sha256(peer_sha256)
    data_digest = _sha256(peer_data_sha256)
    peer_size = _integer(
        peer_size_bytes, 1, DATA_TRANSCRIPT_V1_MAX_PEER_BYTES
    )
    data_size = _integer(
        peer_data_size_bytes, 0, DATA_TRANSCRIPT_V1_MAX_PEER_DATA_BYTES
    )
    return {
        "category": category,
        "control_mutation": DATA_TRANSCRIPT_V1_CONTROL_MUTATION,
        "execution": "direct_execve_peer_with_fresh_state_argv_v1",
        "network": "none",
        "peer": {"sha256": peer_digest, "size_bytes": peer_size},
        "peer_data": {
            "sha256": data_digest,
            "size_bytes": data_size,
        },
        "reset_mode": DATA_TRANSCRIPT_V1_RESET_MODE,
        "schema_version": DATA_TRANSCRIPT_V1_SCHEMA_VERSION,
    }


def data_transcript_v1_reset_commitment_sha256(
    *,
    category: str,
    peer_sha256: str,
    peer_size_bytes: int,
    peer_data_sha256: str,
    peer_data_size_bytes: int,
) -> str:
    descriptor = data_transcript_v1_reset_descriptor(
        category=category,
        peer_sha256=peer_sha256,
        peer_size_bytes=peer_size_bytes,
        peer_data_sha256=peer_data_sha256,
        peer_data_size_bytes=peer_data_size_bytes,
    )
    return hashlib.sha256(
        data_transcript_v1_canonical_json_bytes(descriptor)
    ).hexdigest()


def parse_data_transcript_v1_recipe(
    payload: bytes,
) -> DataTranscriptRecipe:
    """Parse a bounded closed send/expect transcript recipe."""

    try:
        value = parse_canonical_ascii_json(
            payload,
            maximum_bytes=DATA_TRANSCRIPT_V1_MAX_DOCUMENT_BYTES,
            maximum_depth=DATA_TRANSCRIPT_V1_MAX_JSON_DEPTH,
        )
    except InteractionDataCommonError as error:
        raise DataTranscriptContractError("invalid_recipe_json") from error
    root = _mapping(value, _RECIPE_KEYS)
    if root["schema_version"] != DATA_TRANSCRIPT_V1_SCHEMA_VERSION:
        _fail("contract_mismatch")
    contract = _mapping(root["contract"], _CONTRACT_KEYS)
    if contract != {
        "id": DATA_TRANSCRIPT_V1_CONTRACT_ID,
        "protocol": DATA_TRANSCRIPT_V1_PROTOCOL,
        "version": DATA_TRANSCRIPT_V1_CONTRACT_VERSION,
    }:
        _fail("contract_mismatch")
    category = root["category"]
    if category not in DATA_TRANSCRIPT_V1_CATEGORIES:
        _fail("invalid_category")
    preissue_id = _safe_id(root["preissue_id"])
    reset_commitment = _sha256(root["reset_commitment_sha256"])
    _integer(
        root["timeout_milliseconds"],
        1,
        DATA_TRANSCRIPT_V1_MAX_TIMEOUT_MILLISECONDS,
    )
    steps = root["steps"]
    if (
        type(steps) is not list
        or not 2 <= len(steps) <= DATA_TRANSCRIPT_V1_MAX_STEPS
    ):
        _fail("invalid_steps")
    ids: set[str] = set()
    aggregate_send = 0
    aggregate_expect = 0
    first_send_id: str | None = None
    first_send_index: int | None = None
    last_expect_index: int | None = None
    for index, item in enumerate(steps):
        if type(item) is not dict:
            _fail("invalid_step")
        step_id = item.get("id")
        if (
            type(step_id) is not str
            or _SAFE_STEP_ID.fullmatch(step_id) is None
            or step_id in ids
        ):
            _fail("invalid_step_id")
        ids.add(step_id)
        op = item.get("op")
        if op == "send":
            raw = _mapping(item, _SEND_KEYS)
            size = len(_literal_bytes(raw["data"]))
            aggregate_send += size
            if first_send_id is None:
                first_send_id = step_id
                first_send_index = index
        elif op == "expect":
            raw = _mapping(item, _EXPECT_KEYS)
            expected = _literal_bytes(raw["data"])
            if raw["stream"] not in {"stdout", "stderr"}:
                _fail("invalid_expect_stream")
            _integer(
                raw["max_read_bytes"],
                len(expected),
                DATA_TRANSCRIPT_V1_MAX_STEP_BYTES,
            )
            aggregate_expect += int(raw["max_read_bytes"])
            last_expect_index = index
        else:
            _fail("unknown_operation")
        if aggregate_send > DATA_TRANSCRIPT_V1_MAX_AGGREGATE_SEND_BYTES:
            _fail("aggregate_send_limit")
        if aggregate_expect > DATA_TRANSCRIPT_V1_MAX_AGGREGATE_EXPECT_BYTES:
            _fail("aggregate_expect_limit")
    if (
        first_send_id is None
        or first_send_index is None
        or last_expect_index is None
        or last_expect_index <= first_send_index
        or steps[-1].get("op") != "expect"
    ):
        _fail("control_not_observable")
    canonical = data_transcript_v1_canonical_json_bytes(value)
    return DataTranscriptRecipe(
        category=str(category),
        preissue_id=preissue_id,
        reset_commitment_sha256=reset_commitment,
        document=value,
        canonical_bytes=canonical,
        sha256=hashlib.sha256(canonical).hexdigest(),
        step_count=len(steps),
        aggregate_send_bytes=aggregate_send,
        aggregate_expect_bytes=aggregate_expect,
        first_send_step_id=first_send_id,
    )


def parse_data_transcript_v1_preissue(
    payload: bytes,
) -> DataTranscriptPreissueManifest:
    """Parse the private operator preissue and recompute reset binding."""

    try:
        value = parse_canonical_ascii_json(
            payload,
            maximum_bytes=DATA_TRANSCRIPT_V1_MAX_PREISSUE_BYTES,
            maximum_depth=DATA_TRANSCRIPT_V1_MAX_JSON_DEPTH,
        )
    except InteractionDataCommonError as error:
        raise DataTranscriptContractError("invalid_preissue_json") from error
    root = _mapping(value, _PREISSUE_KEYS, code="invalid_preissue_schema")
    contract = _mapping(
        root["contract"],
        _CONTRACT_KEYS,
        code="invalid_preissue_schema",
    )
    if (
        root["schema_version"] != DATA_TRANSCRIPT_V1_SCHEMA_VERSION
        or contract
        != {
            "id": DATA_TRANSCRIPT_V1_PREISSUE_CONTRACT_ID,
            "protocol": DATA_TRANSCRIPT_V1_PREISSUE_PROTOCOL,
            "version": DATA_TRANSCRIPT_V1_CONTRACT_VERSION,
        }
    ):
        _fail("preissue_contract_mismatch")
    category = root["category"]
    if category not in DATA_TRANSCRIPT_V1_CATEGORIES:
        _fail("invalid_category")
    preissue_id = _safe_id(root["preissue_id"])
    issue_revision = _integer(root["issue_revision"], 1, 2**63 - 1)
    configuration_epoch = _integer(
        root["configuration_epoch"], 0, 2**63 - 1
    )
    issued_at = root["issued_at"]
    if type(issued_at) is not str or not issued_at or len(issued_at) > 64:
        _fail("invalid_preissue_time")
    source_manifest = _sha256(root["source_manifest_sha256"])
    image_digest = root["image_digest"]
    if (
        type(image_digest) is not str
        or _IMAGE_DIGEST.fullmatch(image_digest) is None
    ):
        _fail("invalid_image_digest")
    seal_nonce = _sha256(root["seal_nonce"])
    peer = _mapping(
        root["peer"],
        _PRIVATE_INPUT_KEYS,
        code="invalid_preissue_input",
    )
    peer_data = _mapping(
        root["peer_data"],
        _PRIVATE_INPUT_KEYS,
        code="invalid_preissue_input",
    )
    peer_sha = _sha256(peer["sha256"], code="invalid_preissue_input")
    peer_size = _integer(
        peer["size_bytes"],
        1,
        DATA_TRANSCRIPT_V1_MAX_PEER_BYTES,
        code="invalid_preissue_input",
    )
    data_sha = _sha256(
        peer_data["sha256"], code="invalid_preissue_input"
    )
    data_size = _integer(
        peer_data["size_bytes"],
        0,
        DATA_TRANSCRIPT_V1_MAX_PEER_DATA_BYTES,
        code="invalid_preissue_input",
    )
    reset = _mapping(
        root["reset"],
        _RESET_KEYS,
        code="invalid_reset_contract",
    )
    expected_commitment = data_transcript_v1_reset_commitment_sha256(
        category=str(category),
        peer_sha256=peer_sha,
        peer_size_bytes=peer_size,
        peer_data_sha256=data_sha,
        peer_data_size_bytes=data_size,
    )
    if reset != {
        "commitment_sha256": expected_commitment,
        "control_mutation": DATA_TRANSCRIPT_V1_CONTROL_MUTATION,
        "execution": "direct_execve_peer_with_fresh_state_argv_v1",
        "mode": DATA_TRANSCRIPT_V1_RESET_MODE,
        "network": "none",
    }:
        _fail("invalid_reset_contract")
    canonical = data_transcript_v1_canonical_json_bytes(value)
    return DataTranscriptPreissueManifest(
        category=str(category),
        preissue_id=preissue_id,
        issue_revision=issue_revision,
        issued_at=issued_at,
        configuration_epoch=configuration_epoch,
        source_manifest_sha256=source_manifest,
        image_digest=str(image_digest),
        peer_sha256=peer_sha,
        peer_size_bytes=peer_size,
        peer_data_sha256=data_sha,
        peer_data_size_bytes=data_size,
        reset_commitment_sha256=expected_commitment,
        seal_nonce=seal_nonce,
        document=value,
        canonical_bytes=canonical,
        sha256=hashlib.sha256(canonical).hexdigest(),
    )


def data_transcript_v1_contract_descriptor() -> dict[str, object]:
    return {
        "categories": sorted(DATA_TRANSCRIPT_V1_CATEGORIES),
        "contract_id": DATA_TRANSCRIPT_V1_CONTRACT_ID,
        "contract_version": DATA_TRANSCRIPT_V1_CONTRACT_VERSION,
        "control_authority": "pinned_image_producer",
        "control_mutation": DATA_TRANSCRIPT_V1_CONTROL_MUTATION,
        "limits": {
            "aggregate_expect_bytes": (
                DATA_TRANSCRIPT_V1_MAX_AGGREGATE_EXPECT_BYTES
            ),
            "aggregate_send_bytes": (
                DATA_TRANSCRIPT_V1_MAX_AGGREGATE_SEND_BYTES
            ),
            "document_bytes": DATA_TRANSCRIPT_V1_MAX_DOCUMENT_BYTES,
            "step_bytes": DATA_TRANSCRIPT_V1_MAX_STEP_BYTES,
            "steps": DATA_TRANSCRIPT_V1_MAX_STEPS,
            "timeout_milliseconds": (
                DATA_TRANSCRIPT_V1_MAX_TIMEOUT_MILLISECONDS
            ),
        },
        "network": "none",
        "operations": ["expect", "send"],
        "preissue_protocol": DATA_TRANSCRIPT_V1_PREISSUE_PROTOCOL,
        "protocol": DATA_TRANSCRIPT_V1_PROTOCOL,
        "reset_mode": DATA_TRANSCRIPT_V1_RESET_MODE,
        "schema_version": DATA_TRANSCRIPT_V1_SCHEMA_VERSION,
        "transport": "canonical-ascii-json-newline-v1",
    }


DATA_TRANSCRIPT_V1_CONTRACT_FINGERPRINT = hashlib.sha256(
    data_transcript_v1_canonical_json_bytes(
        data_transcript_v1_contract_descriptor()
    )
).hexdigest()


__all__ = [
    "DATA_TRANSCRIPT_V1_CATEGORIES",
    "DATA_TRANSCRIPT_V1_CONTRACT_FINGERPRINT",
    "DATA_TRANSCRIPT_V1_CONTRACT_ID",
    "DATA_TRANSCRIPT_V1_CONTRACT_VERSION",
    "DATA_TRANSCRIPT_V1_CONTROL_MUTATION",
    "DATA_TRANSCRIPT_V1_MAX_AGGREGATE_EXPECT_BYTES",
    "DATA_TRANSCRIPT_V1_MAX_AGGREGATE_SEND_BYTES",
    "DATA_TRANSCRIPT_V1_MAX_DOCUMENT_BYTES",
    "DATA_TRANSCRIPT_V1_MAX_PEER_BYTES",
    "DATA_TRANSCRIPT_V1_MAX_PEER_DATA_BYTES",
    "DATA_TRANSCRIPT_V1_MAX_PREISSUE_BYTES",
    "DATA_TRANSCRIPT_V1_MAX_STEP_BYTES",
    "DATA_TRANSCRIPT_V1_MAX_STEPS",
    "DATA_TRANSCRIPT_V1_MAX_TIMEOUT_MILLISECONDS",
    "DATA_TRANSCRIPT_V1_PREISSUE_CONTRACT_ID",
    "DATA_TRANSCRIPT_V1_PREISSUE_PROTOCOL",
    "DATA_TRANSCRIPT_V1_PROTOCOL",
    "DATA_TRANSCRIPT_V1_RESET_MODE",
    "DATA_TRANSCRIPT_V1_SCHEMA_VERSION",
    "DataTranscriptContractError",
    "DataTranscriptPreissueManifest",
    "DataTranscriptRecipe",
    "data_transcript_v1_canonical_json_bytes",
    "data_transcript_v1_contract_descriptor",
    "data_transcript_v1_reset_commitment_sha256",
    "data_transcript_v1_reset_descriptor",
    "parse_data_transcript_v1_preissue",
    "parse_data_transcript_v1_recipe",
]
