"""Fail-closed validation of image-produced Crypto/Misc transcripts.

This module never executes a peer.  It re-hashes the exact stdout, stderr,
transcript, and reset-proof artifacts; replays the closed send/expect recipe;
and accepts only three clean matches plus three producer-owned negative
controls from six distinct fresh instances.  Receipts deliberately expose
commitments, not raw oracle streams.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Iterable, Mapping

from ctf_os.contracts.data_transcript_v1 import (
    DATA_TRANSCRIPT_V1_CONTRACT_FINGERPRINT,
    DATA_TRANSCRIPT_V1_CONTROL_MUTATION,
    DATA_TRANSCRIPT_V1_MAX_AGGREGATE_SEND_BYTES,
    DATA_TRANSCRIPT_V1_MAX_DOCUMENT_BYTES,
    DATA_TRANSCRIPT_V1_MAX_STEP_BYTES,
    DataTranscriptContractError,
    data_transcript_v1_canonical_json_bytes,
    parse_data_transcript_v1_recipe,
)
from ctf_os.contracts.interaction_data_common import (
    InteractionDataCommonError,
    parse_canonical_ascii_json,
)


DATA_TRANSCRIPT_PRODUCER_CONTRACT_ID = "ctfos.data_transcript.producer"
DATA_TRANSCRIPT_PRODUCER_CONTRACT_VERSION = 1
DATA_TRANSCRIPT_PRODUCER_PROTOCOL = (
    "crypto_misc_local_data_transcript_producer_v1"
)
DATA_TRANSCRIPT_EVALUATION_PROTOCOL = (
    "ctfos.data_transcript.evaluation.v1"
)
DATA_TRANSCRIPT_STATE_KEY = "data_transcript_evaluations"
DATA_TRANSCRIPT_MAX_HISTORY = 64
DATA_TRANSCRIPT_RUNS_PER_PHASE = 3
DATA_TRANSCRIPT_MAX_RESULT_BYTES = 64 * 1024
DATA_TRANSCRIPT_MAX_STREAM_BYTES = 1024 * 1024
DATA_TRANSCRIPT_MAX_TRANSCRIPT_BYTES = 8 * 1024 * 1024
DATA_TRANSCRIPT_MAX_RESET_PROOF_BYTES = 64 * 1024

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SAFE_STEP_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_SAFE_REASON = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
_DOCUMENT_KEYS = frozenset(
    {
        "binding",
        "contract",
        "observation",
        "reason_code",
        "schema_version",
        "status",
    }
)
_CONTRACT_KEYS = frozenset(
    {"id", "recipe_contract_fingerprint", "protocol", "version"}
)
_BINDING_KEYS = frozenset(
    {
        "category",
        "configuration_epoch",
        "image_digest",
        "network",
        "ordinal",
        "peer_data_sha256",
        "peer_data_size_bytes",
        "peer_sha256",
        "peer_size_bytes",
        "phase",
        "preissue_id",
        "preissue_sha256",
        "producer_sha256",
        "recipe_sha256",
        "recipe_size_bytes",
        "reset_commitment_sha256",
    }
)
_OBSERVATION_KEYS = frozenset(
    {
        "control_mutation_applied",
        "control_mutation_step_id",
        "elapsed_milliseconds",
        "fresh_instance_nonce_sha256",
        "fresh_state_initial_sha256",
        "mismatch_step_id",
        "peer_exit_code",
        "peer_signal",
        "process_group_cleaned",
        "reset_proof_path",
        "reset_proof_sha256",
        "reset_proof_size_bytes",
        "stderr_path",
        "stderr_sha256",
        "stderr_size_bytes",
        "stdout_path",
        "stdout_sha256",
        "stdout_size_bytes",
        "timed_out",
        "transcript_path",
        "transcript_sha256",
        "transcript_size_bytes",
        "truncated",
    }
)
_TRANSCRIPT_KEYS = frozenset({"binding", "events", "schema_version"})
_TRANSCRIPT_BINDING_KEYS = frozenset(
    {
        "category",
        "ordinal",
        "phase",
        "preissue_id",
        "recipe_sha256",
        "reset_commitment_sha256",
    }
)
_EVENT_KEYS = frozenset(
    {
        "data_hex",
        "direction",
        "offset",
        "sequence",
        "sha256",
        "size_bytes",
        "step_id",
        "stream",
    }
)
_RESET_PROOF_KEYS = frozenset(
    {
        "binding",
        "fresh_instance_nonce_sha256",
        "fresh_state_initial_sha256",
        "peer_data_sha256",
        "peer_sha256",
        "protocol",
        "schema_version",
    }
)
_RESET_BINDING_KEYS = frozenset(
    {
        "category",
        "ordinal",
        "phase",
        "preissue_id",
        "reset_commitment_sha256",
    }
)


class DataTranscriptEvaluationError(ValueError):
    """A stable evidence rejection code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class DataTranscriptExpectedBinding:
    category: str
    configuration_epoch: int
    image_digest: str
    preissue_id: str
    preissue_sha256: str
    producer_sha256: str
    recipe_sha256: str
    recipe_size_bytes: int
    peer_sha256: str
    peer_size_bytes: int
    peer_data_sha256: str
    peer_data_size_bytes: int
    reset_commitment_sha256: str


@dataclass(frozen=True, slots=True)
class DataTranscriptReplayEvidence:
    document_bytes: bytes
    stdout_bytes: bytes
    stderr_bytes: bytes
    transcript_bytes: bytes
    reset_proof_bytes: bytes


@dataclass(frozen=True, slots=True)
class DataTranscriptReplayReceipt:
    phase: str
    ordinal: int
    status: str
    reason_code: str
    fresh_instance_nonce_sha256: str
    stdout_sha256: str
    stderr_sha256: str
    transcript_sha256: str
    reset_proof_sha256: str
    mismatch_step_id: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "fresh_instance_nonce_sha256": (
                self.fresh_instance_nonce_sha256
            ),
            "mismatch_step_id": self.mismatch_step_id,
            "ordinal": self.ordinal,
            "phase": self.phase,
            "reason_code": self.reason_code,
            "reset_proof_sha256": self.reset_proof_sha256,
            "status": self.status,
            "stderr_sha256": self.stderr_sha256,
            "stdout_sha256": self.stdout_sha256,
            "transcript_sha256": self.transcript_sha256,
        }


@dataclass(frozen=True, slots=True)
class DataTranscriptEvaluation:
    passed: bool
    reason_code: str
    reset_commitment_sha256: str
    positive_receipts: tuple[DataTranscriptReplayReceipt, ...]
    control_receipts: tuple[DataTranscriptReplayReceipt, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "control_receipts": [
                item.to_dict() for item in self.control_receipts
            ],
            "passed": self.passed,
            "positive_receipts": [
                item.to_dict() for item in self.positive_receipts
            ],
            "protocol": DATA_TRANSCRIPT_EVALUATION_PROTOCOL,
            "reason_code": self.reason_code,
            "reset_commitment_sha256": (
                self.reset_commitment_sha256
            ),
            "schema_version": 1,
        }

    def canonical_bytes(self) -> bytes:
        payload = data_transcript_v1_canonical_json_bytes(self.to_dict())
        if len(payload) > DATA_TRANSCRIPT_MAX_RESULT_BYTES:
            _fail("evaluation_size_limit")
        return payload


def _fail(code: str) -> None:
    raise DataTranscriptEvaluationError(code)


def _hash_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _hash(value: object, code: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        _fail(code)
    return value


def _integer(
    value: object,
    minimum: int,
    maximum: int,
    code: str,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(code)
    return value


def _exact(
    value: object,
    keys: frozenset[str],
    code: str,
) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != keys:
        _fail(code)
    return value


def _parse_canonical(
    payload: bytes,
    maximum: int,
    code: str,
) -> object:
    try:
        return parse_canonical_ascii_json(
            payload,
            maximum_bytes=maximum,
            maximum_depth=16,
        )
    except InteractionDataCommonError as error:
        raise DataTranscriptEvaluationError(code) from error


def _literal(value: object) -> bytes:
    if type(value) is not dict or frozenset(value) != {
        "encoding",
        "value",
    }:
        _fail("recipe_runtime_invalid")
    encoding = value["encoding"]
    encoded = value["value"]
    if type(encoded) is not str or encoding not in {"hex", "utf8"}:
        _fail("recipe_runtime_invalid")
    try:
        result = (
            bytes.fromhex(encoded)
            if encoding == "hex"
            else encoded.encode("utf-8")
        )
    except (UnicodeError, ValueError):
        _fail("recipe_runtime_invalid")
    if not result or len(result) > DATA_TRANSCRIPT_V1_MAX_STEP_BYTES:
        _fail("recipe_runtime_invalid")
    return result


def _validate_expected_binding(
    expected: DataTranscriptExpectedBinding,
) -> None:
    if type(expected) is not DataTranscriptExpectedBinding:
        _fail("expected_binding_invalid")
    if expected.category not in {"crypto", "misc"}:
        _fail("expected_binding_invalid")
    _integer(
        expected.configuration_epoch,
        0,
        2**63 - 1,
        "expected_binding_invalid",
    )
    if (
        type(expected.image_digest) is not str
        or _IMAGE_DIGEST.fullmatch(expected.image_digest) is None
        or type(expected.preissue_id) is not str
        or _SAFE_ID.fullmatch(expected.preissue_id) is None
    ):
        _fail("expected_binding_invalid")
    for digest in (
        expected.preissue_sha256,
        expected.producer_sha256,
        expected.recipe_sha256,
        expected.peer_sha256,
        expected.peer_data_sha256,
        expected.reset_commitment_sha256,
    ):
        _hash(digest, "expected_binding_invalid")
    _integer(
        expected.recipe_size_bytes,
        1,
        DATA_TRANSCRIPT_V1_MAX_DOCUMENT_BYTES,
        "expected_binding_invalid",
    )
    _integer(
        expected.peer_size_bytes,
        1,
        1024 * 1024 * 1024,
        "expected_binding_invalid",
    )
    _integer(
        expected.peer_data_size_bytes,
        0,
        1024 * 1024 * 1024,
        "expected_binding_invalid",
    )


def _expected_document_binding(
    expected: DataTranscriptExpectedBinding,
    *,
    phase: str,
    ordinal: int,
) -> dict[str, object]:
    return {
        "category": expected.category,
        "configuration_epoch": expected.configuration_epoch,
        "image_digest": expected.image_digest,
        "network": "none",
        "ordinal": ordinal,
        "peer_data_sha256": expected.peer_data_sha256,
        "peer_data_size_bytes": expected.peer_data_size_bytes,
        "peer_sha256": expected.peer_sha256,
        "peer_size_bytes": expected.peer_size_bytes,
        "phase": phase,
        "preissue_id": expected.preissue_id,
        "preissue_sha256": expected.preissue_sha256,
        "producer_sha256": expected.producer_sha256,
        "recipe_sha256": expected.recipe_sha256,
        "recipe_size_bytes": expected.recipe_size_bytes,
        "reset_commitment_sha256": (
            expected.reset_commitment_sha256
        ),
    }


def parse_data_transcript_producer_document(
    payload: bytes,
    *,
    expected_binding: DataTranscriptExpectedBinding,
    expected_phase: str,
    expected_ordinal: int,
) -> Mapping[str, object]:
    """Parse and bind one producer result without trusting its labels."""

    _validate_expected_binding(expected_binding)
    if expected_phase not in {"positive", "control"}:
        _fail("phase_invalid")
    _integer(expected_ordinal, 1, 3, "ordinal_invalid")
    root = _exact(
        _parse_canonical(
            payload,
            DATA_TRANSCRIPT_MAX_RESULT_BYTES,
            "producer_document_invalid",
        ),
        _DOCUMENT_KEYS,
        "producer_document_schema_invalid",
    )
    if root["schema_version"] != 1:
        _fail("producer_contract_mismatch")
    contract = _exact(
        root["contract"],
        _CONTRACT_KEYS,
        "producer_contract_mismatch",
    )
    if contract != {
        "id": DATA_TRANSCRIPT_PRODUCER_CONTRACT_ID,
        "protocol": DATA_TRANSCRIPT_PRODUCER_PROTOCOL,
        "recipe_contract_fingerprint": (
            DATA_TRANSCRIPT_V1_CONTRACT_FINGERPRINT
        ),
        "version": DATA_TRANSCRIPT_PRODUCER_CONTRACT_VERSION,
    }:
        _fail("producer_contract_mismatch")
    binding = _exact(
        root["binding"],
        _BINDING_KEYS,
        "producer_binding_invalid",
    )
    if binding != _expected_document_binding(
        expected_binding,
        phase=expected_phase,
        ordinal=expected_ordinal,
    ):
        _fail("producer_binding_mismatch")
    status = root["status"]
    reason = root["reason_code"]
    if (
        status not in {"failed", "matched", "rejected", "unverifiable"}
        or type(reason) is not str
        or _SAFE_REASON.fullmatch(reason) is None
    ):
        _fail("producer_status_invalid")
    _exact(
        root["observation"],
        _OBSERVATION_KEYS,
        "producer_observation_schema_invalid",
    )
    return root


def _validate_attached(
    observation: Mapping[str, object],
    *,
    name: str,
    payload: bytes,
    maximum: int,
    path: str,
) -> None:
    if type(payload) is not bytes or len(payload) > maximum:
        _fail(f"{name}_artifact_invalid")
    if observation[f"{name}_path"] != path:
        _fail(f"{name}_path_mismatch")
    if (
        observation[f"{name}_sha256"] != _hash_bytes(payload)
        or observation[f"{name}_size_bytes"] != len(payload)
        or type(observation[f"{name}_size_bytes"]) is not int
    ):
        _fail(f"{name}_artifact_mismatch")


def _transcript_binding(
    expected: DataTranscriptExpectedBinding,
    *,
    phase: str,
    ordinal: int,
) -> dict[str, object]:
    return {
        "category": expected.category,
        "ordinal": ordinal,
        "phase": phase,
        "preissue_id": expected.preissue_id,
        "recipe_sha256": expected.recipe_sha256,
        "reset_commitment_sha256": (
            expected.reset_commitment_sha256
        ),
    }


def _validate_transcript(
    payload: bytes,
    *,
    expected: DataTranscriptExpectedBinding,
    phase: str,
    ordinal: int,
    stdout: bytes,
    stderr: bytes,
    recipe: Mapping[str, object],
) -> str | None:
    root = _exact(
        _parse_canonical(
            payload,
            DATA_TRANSCRIPT_MAX_TRANSCRIPT_BYTES,
            "transcript_invalid",
        ),
        _TRANSCRIPT_KEYS,
        "transcript_schema_invalid",
    )
    if root["schema_version"] != 1:
        _fail("transcript_schema_invalid")
    binding = _exact(
        root["binding"],
        _TRANSCRIPT_BINDING_KEYS,
        "transcript_binding_invalid",
    )
    if binding != _transcript_binding(
        expected, phase=phase, ordinal=ordinal
    ):
        _fail("transcript_binding_mismatch")
    raw_events = root["events"]
    if type(raw_events) is not list or len(raw_events) > 262_144:
        _fail("transcript_events_invalid")
    streams = {
        "stdin": bytearray(),
        "stdout": bytearray(),
        "stderr": bytearray(),
    }
    significant: list[tuple[str, str, str, bytes]] = []
    for sequence, raw in enumerate(raw_events, start=1):
        event = _exact(raw, _EVENT_KEYS, "transcript_event_invalid")
        if event["sequence"] != sequence:
            _fail("transcript_sequence_invalid")
        direction = event["direction"]
        stream = event["stream"]
        if (direction, stream) not in {
            ("send", "stdin"),
            ("receive", "stdout"),
            ("receive", "stderr"),
        }:
            _fail("transcript_direction_invalid")
        encoded = event["data_hex"]
        if (
            type(encoded) is not str
            or len(encoded) % 2
            or encoded != encoded.lower()
            or len(encoded) > 2 * DATA_TRANSCRIPT_V1_MAX_STEP_BYTES
        ):
            _fail("transcript_data_invalid")
        try:
            chunk = bytes.fromhex(encoded)
        except ValueError:
            _fail("transcript_data_invalid")
        if len(chunk) > DATA_TRANSCRIPT_V1_MAX_STEP_BYTES:
            _fail("transcript_chunk_invalid")
        current = streams[stream]
        if (
            event["offset"] != len(current)
            or event["size_bytes"] != len(chunk)
            or event["sha256"] != _hash_bytes(chunk)
            or type(event["offset"]) is not int
            or type(event["size_bytes"]) is not int
        ):
            _fail("transcript_event_mismatch")
        current.extend(chunk)
        step_id = event["step_id"]
        if step_id is not None:
            if (
                type(step_id) is not str
                or _SAFE_STEP_ID.fullmatch(step_id) is None
            ):
                _fail("transcript_step_id_invalid")
            significant.append((step_id, direction, stream, chunk))
    if (
        bytes(streams["stdout"]) != stdout
        or bytes(streams["stderr"]) != stderr
        or len(streams["stdin"])
        > DATA_TRANSCRIPT_V1_MAX_AGGREGATE_SEND_BYTES
    ):
        _fail("transcript_stream_mismatch")

    cursor = 0
    mismatch_step_id: str | None = None
    mutation_seen = False
    first_send_seen = False
    for raw_step in recipe["steps"]:
        if cursor >= len(significant):
            if phase == "control" and mismatch_step_id is not None:
                break
            _fail("transcript_step_missing")
        step_id = str(raw_step["id"])
        actual_id, direction, stream, chunk = significant[cursor]
        if actual_id != step_id:
            _fail("transcript_step_order_invalid")
        cursor += 1
        expected_bytes = _literal(raw_step["data"])
        if raw_step["op"] == "send":
            expected_send = expected_bytes
            if not first_send_seen:
                first_send_seen = True
                if phase == "control":
                    mutated = bytearray(expected_send)
                    mutated[0] ^= 1 << (ordinal - 1)
                    expected_send = bytes(mutated)
                    mutation_seen = True
            if (
                direction != "send"
                or stream != "stdin"
                or chunk != expected_send
            ):
                _fail("transcript_send_invalid")
        else:
            if (
                direction != "receive"
                or stream != raw_step["stream"]
                or len(chunk) > int(raw_step["max_read_bytes"])
            ):
                _fail("transcript_expect_invalid")
            if chunk != expected_bytes:
                if not any(
                    actual != expected
                    for actual, expected in zip(
                        chunk, expected_bytes, strict=False
                    )
                ):
                    _fail("negative_control_not_byte_rejected")
                mismatch_step_id = step_id
                if phase == "positive":
                    _fail("positive_expectation_mismatch")
                break
    if cursor != len(significant):
        _fail("transcript_unbound_event")
    if phase == "positive":
        if mismatch_step_id is not None:
            _fail("positive_expectation_mismatch")
    elif not mutation_seen or mismatch_step_id is None:
        _fail("negative_control_not_rejected")
    return mismatch_step_id


def _validate_reset_proof(
    payload: bytes,
    *,
    expected: DataTranscriptExpectedBinding,
    phase: str,
    ordinal: int,
) -> str:
    root = _exact(
        _parse_canonical(
            payload,
            DATA_TRANSCRIPT_MAX_RESET_PROOF_BYTES,
            "reset_proof_invalid",
        ),
        _RESET_PROOF_KEYS,
        "reset_proof_schema_invalid",
    )
    if (
        root["schema_version"] != 1
        or root["protocol"] != "ctfos.data_transcript.reset_proof.v1"
    ):
        _fail("reset_proof_schema_invalid")
    binding = _exact(
        root["binding"],
        _RESET_BINDING_KEYS,
        "reset_proof_binding_invalid",
    )
    if binding != {
        "category": expected.category,
        "ordinal": ordinal,
        "phase": phase,
        "preissue_id": expected.preissue_id,
        "reset_commitment_sha256": (
            expected.reset_commitment_sha256
        ),
    }:
        _fail("reset_proof_binding_mismatch")
    nonce = _hash(
        root["fresh_instance_nonce_sha256"],
        "reset_nonce_invalid",
    )
    if (
        root["fresh_state_initial_sha256"]
        != expected.peer_data_sha256
        or root["peer_data_sha256"] != expected.peer_data_sha256
        or root["peer_sha256"] != expected.peer_sha256
    ):
        _fail("reset_state_mismatch")
    return nonce


def _terminal_valid(observation: Mapping[str, object]) -> bool:
    exit_code = observation["peer_exit_code"]
    peer_signal = observation["peer_signal"]
    return (
        (exit_code is None and peer_signal is None)
        or (
            type(exit_code) is int
            and 0 <= exit_code <= 255
            and peer_signal is None
        )
        or (
            type(peer_signal) is int
            and 1 <= peer_signal <= 64
            and exit_code is None
        )
    )


def _validate_replay(
    evidence: DataTranscriptReplayEvidence,
    *,
    expected: DataTranscriptExpectedBinding,
    phase: str,
    ordinal: int,
    recipe: Mapping[str, object],
) -> DataTranscriptReplayReceipt:
    if type(evidence) is not DataTranscriptReplayEvidence:
        _fail("replay_evidence_invalid")
    root = parse_data_transcript_producer_document(
        evidence.document_bytes,
        expected_binding=expected,
        expected_phase=phase,
        expected_ordinal=ordinal,
    )
    observation = root["observation"]
    base_path = (
        f".ctf/data-transcript-v1/{expected.preissue_id}/"
        f"{expected.recipe_sha256}/{phase}-{ordinal}"
    )
    _validate_attached(
        observation,
        name="stdout",
        payload=evidence.stdout_bytes,
        maximum=DATA_TRANSCRIPT_MAX_STREAM_BYTES,
        path=f"{base_path}/peer.stdout.bin",
    )
    _validate_attached(
        observation,
        name="stderr",
        payload=evidence.stderr_bytes,
        maximum=DATA_TRANSCRIPT_MAX_STREAM_BYTES,
        path=f"{base_path}/peer.stderr.bin",
    )
    _validate_attached(
        observation,
        name="transcript",
        payload=evidence.transcript_bytes,
        maximum=DATA_TRANSCRIPT_MAX_TRANSCRIPT_BYTES,
        path=f"{base_path}/transcript.json",
    )
    _validate_attached(
        observation,
        name="reset_proof",
        payload=evidence.reset_proof_bytes,
        maximum=DATA_TRANSCRIPT_MAX_RESET_PROOF_BYTES,
        path=f"{base_path}/reset-proof.json",
    )
    if (
        type(observation["timed_out"]) is not bool
        or type(observation["truncated"]) is not bool
        or type(observation["process_group_cleaned"]) is not bool
        or observation["timed_out"]
        or observation["truncated"]
        or observation["process_group_cleaned"] is not True
    ):
        _fail("replay_incomplete")
    _integer(
        observation["elapsed_milliseconds"],
        0,
        125_000,
        "elapsed_invalid",
    )
    if not _terminal_valid(observation):
        _fail("terminal_metadata_invalid")
    nonce = _validate_reset_proof(
        evidence.reset_proof_bytes,
        expected=expected,
        phase=phase,
        ordinal=ordinal,
    )
    if (
        observation["fresh_instance_nonce_sha256"] != nonce
        or observation["fresh_state_initial_sha256"]
        != expected.peer_data_sha256
    ):
        _fail("reset_observation_mismatch")
    mismatch = _validate_transcript(
        evidence.transcript_bytes,
        expected=expected,
        phase=phase,
        ordinal=ordinal,
        stdout=evidence.stdout_bytes,
        stderr=evidence.stderr_bytes,
        recipe=recipe,
    )
    expected_mutation = phase == "control"
    if (
        observation["control_mutation_applied"] is not expected_mutation
        or observation["control_mutation_step_id"]
        != (
            str(next(
                item["id"]
                for item in recipe["steps"]
                if item["op"] == "send"
            ))
            if expected_mutation
            else None
        )
        or observation["mismatch_step_id"] != mismatch
    ):
        _fail("control_observation_mismatch")
    if phase == "positive":
        if (
            root["status"] != "matched"
            or root["reason_code"] != "all_steps_matched"
            or mismatch is not None
        ):
            _fail("positive_observation_invalid")
    elif (
        root["status"] != "rejected"
        or root["reason_code"] != "control_mutation_rejected"
        or mismatch is None
    ):
        _fail("negative_control_invalid")
    return DataTranscriptReplayReceipt(
        phase=phase,
        ordinal=ordinal,
        status=str(root["status"]),
        reason_code=str(root["reason_code"]),
        fresh_instance_nonce_sha256=nonce,
        stdout_sha256=_hash_bytes(evidence.stdout_bytes),
        stderr_sha256=_hash_bytes(evidence.stderr_bytes),
        transcript_sha256=_hash_bytes(evidence.transcript_bytes),
        reset_proof_sha256=_hash_bytes(evidence.reset_proof_bytes),
        mismatch_step_id=mismatch,
    )


def evaluate_data_transcript_replays(
    evidence: Iterable[DataTranscriptReplayEvidence],
    *,
    expected_binding: DataTranscriptExpectedBinding,
    recipe_bytes: bytes,
) -> DataTranscriptEvaluation:
    """Validate exactly three fresh positives and three negative controls."""

    _validate_expected_binding(expected_binding)
    if (
        type(recipe_bytes) is not bytes
        or len(recipe_bytes) != expected_binding.recipe_size_bytes
        or _hash_bytes(recipe_bytes) != expected_binding.recipe_sha256
    ):
        _fail("recipe_binding_mismatch")
    try:
        parsed = parse_data_transcript_v1_recipe(recipe_bytes)
    except DataTranscriptContractError as error:
        raise DataTranscriptEvaluationError(
            "recipe_contract_invalid"
        ) from error
    if (
        parsed.category != expected_binding.category
        or parsed.preissue_id != expected_binding.preissue_id
        or parsed.reset_commitment_sha256
        != expected_binding.reset_commitment_sha256
    ):
        _fail("recipe_preissue_binding_mismatch")
    try:
        items = tuple(evidence)
    except (RuntimeError, TypeError) as error:
        raise DataTranscriptEvaluationError(
            "replay_evidence_invalid"
        ) from error
    if len(items) != DATA_TRANSCRIPT_RUNS_PER_PHASE * 2:
        _fail("replay_count_mismatch")
    positives: list[DataTranscriptReplayReceipt] = []
    controls: list[DataTranscriptReplayReceipt] = []
    for index, item in enumerate(items):
        phase = "positive" if index < 3 else "control"
        ordinal = index + 1 if phase == "positive" else index - 2
        receipt = _validate_replay(
            item,
            expected=expected_binding,
            phase=phase,
            ordinal=ordinal,
            recipe=parsed.document,
        )
        (positives if phase == "positive" else controls).append(receipt)
    nonces = {
        item.fresh_instance_nonce_sha256
        for item in (*positives, *controls)
    }
    if len(nonces) != 6:
        _fail("fresh_instance_reused")
    if (
        len({item.stdout_sha256 for item in positives}) != 1
        or len({item.stderr_sha256 for item in positives}) != 1
    ):
        _fail("clean_replay_not_repeatable")
    return DataTranscriptEvaluation(
        passed=True,
        reason_code="validated_three_clean_three_negative_replays",
        reset_commitment_sha256=(
            expected_binding.reset_commitment_sha256
        ),
        positive_receipts=tuple(positives),
        control_receipts=tuple(controls),
    )


__all__ = [
    "DATA_TRANSCRIPT_EVALUATION_PROTOCOL",
    "DATA_TRANSCRIPT_MAX_RESET_PROOF_BYTES",
    "DATA_TRANSCRIPT_MAX_RESULT_BYTES",
    "DATA_TRANSCRIPT_MAX_STREAM_BYTES",
    "DATA_TRANSCRIPT_MAX_TRANSCRIPT_BYTES",
    "DATA_TRANSCRIPT_PRODUCER_CONTRACT_ID",
    "DATA_TRANSCRIPT_PRODUCER_CONTRACT_VERSION",
    "DATA_TRANSCRIPT_PRODUCER_PROTOCOL",
    "DATA_TRANSCRIPT_RUNS_PER_PHASE",
    "DataTranscriptEvaluation",
    "DataTranscriptEvaluationError",
    "DataTranscriptExpectedBinding",
    "DataTranscriptReplayEvidence",
    "DataTranscriptReplayReceipt",
    "evaluate_data_transcript_replays",
    "parse_data_transcript_producer_document",
]
