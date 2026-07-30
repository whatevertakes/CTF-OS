"""Pure validation for image-produced local interaction evidence.

The image producer emits one canonical result document plus four opaque byte
artifacts for every replay.  This module does not execute a process and does
not trust the producer's semantic labels.  It re-hashes every artifact,
reconstructs the transcript, replays the closed recipe data-flow against the
derivation DAG, and evaluates one fixed set of three positive and three
negative-control receipts.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
from dataclasses import dataclass
from typing import Iterable, Mapping

from ctf_os.contracts.pwn_interaction_v1 import (
    PWN_INTERACTION_V1_CONTRACT_FINGERPRINT,
    PWN_INTERACTION_V1_MAX_AGGREGATE_SEND_BYTES,
    PWN_INTERACTION_V1_MAX_SEND_BYTES,
    PWN_INTERACTION_V1_MAX_TIMEOUT_MILLISECONDS,
    PWN_INTERACTION_V1_SENTINEL_REF,
    parse_pwn_interaction_v1_recipe,
)
from ctf_os.store.atomic import StrictJSONError, strict_json_loads


PWN_INTERACTION_PRODUCER_CONTRACT_ID = "ctfos.pwn.interaction"
PWN_INTERACTION_PRODUCER_CONTRACT_VERSION = 1
PWN_INTERACTION_PRODUCER_PROTOCOL = (
    "pwn_local_bounded_interaction_producer_v1"
)
PWN_INTERACTION_RUNS_PER_PHASE = 3
PWN_INTERACTION_MAX_DOCUMENT_BYTES = 64 * 1024
PWN_INTERACTION_MAX_STREAM_BYTES = 1024 * 1024
PWN_INTERACTION_MAX_TRANSCRIPT_BYTES = 8 * 1024 * 1024
PWN_INTERACTION_MAX_DAG_BYTES = 1024 * 1024
PWN_INTERACTION_SENTINEL_COMMAND = (
    b"cat /work/ctfos-pwn-interaction-sentinel-v1\0"
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SAFE_STEP_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_SAFE_REASON = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
_SENTINEL = re.compile(
    rb"CTFOS_PWN_INTERACTION_V1_[0-9a-f]{64}\n"
)
_SENTINEL_PREFIX = b"CTFOS_PWN_INTERACTION_V1_"
_U64_MAX = (1 << 64) - 1

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
_BINDING_KEYS = frozenset(
    {
        "configuration_epoch",
        "image_digest",
        "network",
        "ordinal",
        "phase",
        "preissue_sha256",
        "producer_sha256",
        "recipe_sha256",
        "recipe_size_bytes",
        "source_manifest_sha256",
        "source_sha256",
        "source_size_bytes",
    }
)
_CONTRACT_KEYS = frozenset(
    {"id", "protocol", "recipe_contract_fingerprint", "version"}
)
_OBSERVATION_KEYS = frozenset(
    {
        "control_substitution_applied",
        "derivation_dag_path",
        "derivation_dag_sha256",
        "derivation_dag_size_bytes",
        "elapsed_milliseconds",
        "process_group_cleaned",
        "sentinel_occurrences",
        "sentinel_sha256",
        "stderr_path",
        "stderr_sha256",
        "stderr_size_bytes",
        "stdout_path",
        "stdout_sha256",
        "stdout_size_bytes",
        "target_exit_code",
        "target_signal",
        "timed_out",
        "transcript_path",
        "transcript_sha256",
        "transcript_size_bytes",
    }
)
_TRANSCRIPT_KEYS = frozenset(
    {"binding", "events", "schema_version"}
)
_TRANSCRIPT_BINDING_KEYS = frozenset(
    {"ordinal", "phase", "recipe_sha256"}
)
_EVENT_KEYS = frozenset(
    {
        "data_hex",
        "direction",
        "offset",
        "sequence",
        "sha256",
        "size_bytes",
        "stream",
    }
)
_DAG_KEYS = frozenset({"binding", "nodes", "schema_version"})
_NODE_BASE_KEYS = frozenset(
    {
        "control_substituted",
        "dependencies",
        "name",
        "op",
        "sha256",
        "size_bytes",
        "step_id",
        "type",
    }
)


class PwnInteractionEvaluationError(ValueError):
    """Stable fail-closed evidence validation error."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class PwnInteractionExpectedBinding:
    configuration_epoch: int
    image_digest: str
    preissue_sha256: str
    producer_sha256: str
    recipe_sha256: str
    recipe_size_bytes: int
    source_manifest_sha256: str
    source_sha256: str
    source_size_bytes: int


@dataclass(frozen=True, slots=True)
class PwnInteractionReplayEvidence:
    document_bytes: bytes
    stdout_bytes: bytes
    stderr_bytes: bytes
    transcript_bytes: bytes
    derivation_dag_bytes: bytes


@dataclass(frozen=True, slots=True)
class PwnInteractionReplayReceipt:
    phase: str
    ordinal: int
    status: str
    reason_code: str
    sentinel_sha256: str
    stdout_sha256: str
    stderr_sha256: str
    transcript_sha256: str
    derivation_dag_sha256: str
    target_exit_code: int | None
    target_signal: int | None
    control_substitution_applied: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "control_substitution_applied": (
                self.control_substitution_applied
            ),
            "derivation_dag_sha256": self.derivation_dag_sha256,
            "ordinal": self.ordinal,
            "phase": self.phase,
            "reason_code": self.reason_code,
            "sentinel_sha256": self.sentinel_sha256,
            "status": self.status,
            "stderr_sha256": self.stderr_sha256,
            "stdout_sha256": self.stdout_sha256,
            "target_exit_code": self.target_exit_code,
            "target_signal": self.target_signal,
            "transcript_sha256": self.transcript_sha256,
        }


@dataclass(frozen=True, slots=True)
class PwnInteractionEvaluation:
    passed: bool
    reason_code: str
    attack_receipts: tuple[PwnInteractionReplayReceipt, ...]
    control_receipts: tuple[PwnInteractionReplayReceipt, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "attack_receipts": [
                receipt.to_dict() for receipt in self.attack_receipts
            ],
            "control_receipts": [
                receipt.to_dict() for receipt in self.control_receipts
            ],
            "passed": self.passed,
            "protocol": "ctfos.pwn.interaction.evaluation.v1",
            "reason_code": self.reason_code,
            "schema_version": 1,
        }

    def canonical_bytes(self) -> bytes:
        return _canonical_json_bytes(
            self.to_dict(),
            PWN_INTERACTION_MAX_DOCUMENT_BYTES,
        )


def _fail(code: str) -> None:
    raise PwnInteractionEvaluationError(code)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_json_bytes(value: object, maximum: int) -> bytes:
    try:
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
    except (RecursionError, TypeError, UnicodeError, ValueError):
        _fail("canonical_json_invalid")
    if len(payload) > maximum:
        _fail("artifact_size_limit_exceeded")
    return payload


def _parse_canonical(payload: bytes, maximum: int, code: str) -> object:
    if type(payload) is not bytes or not payload or len(payload) > maximum:
        _fail(code)
    try:
        value = strict_json_loads(payload, max_bytes=maximum, max_depth=16)
    except (StrictJSONError, UnicodeError, ValueError):
        _fail(code)
    if _canonical_json_bytes(value, maximum) != payload:
        _fail(code)
    return value


def _exact(value: object, keys: frozenset[str], code: str) -> dict:
    if type(value) is not dict or frozenset(value) != keys:
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


def _hash(value: object, code: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        _fail(code)
    return value


def _validate_expected_binding(
    expected: PwnInteractionExpectedBinding,
) -> None:
    if type(expected) is not PwnInteractionExpectedBinding:
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
    ):
        _fail("expected_binding_invalid")
    for value in (
        expected.preissue_sha256,
        expected.producer_sha256,
        expected.recipe_sha256,
        expected.source_manifest_sha256,
        expected.source_sha256,
    ):
        _hash(value, "expected_binding_invalid")
    _integer(
        expected.recipe_size_bytes,
        1,
        256 * 1024,
        "expected_binding_invalid",
    )
    _integer(
        expected.source_size_bytes,
        1,
        1024 * 1024 * 1024,
        "expected_binding_invalid",
    )


def parse_pwn_interaction_producer_document(
    payload: bytes,
    *,
    expected_binding: PwnInteractionExpectedBinding,
    expected_phase: str,
    expected_ordinal: int,
) -> Mapping[str, object]:
    """Parse one canonical producer document and bind every immutable field."""

    _validate_expected_binding(expected_binding)
    if expected_phase not in {"attack", "control"}:
        _fail("phase_invalid")
    _integer(expected_ordinal, 1, 3, "ordinal_invalid")
    root = _exact(
        _parse_canonical(
            payload,
            PWN_INTERACTION_MAX_DOCUMENT_BYTES,
            "producer_document_invalid",
        ),
        _DOCUMENT_KEYS,
        "producer_document_schema_invalid",
    )
    if type(root["schema_version"]) is not int or root["schema_version"] != 1:
        _fail("producer_contract_mismatch")
    contract = _exact(
        root["contract"], _CONTRACT_KEYS, "producer_contract_mismatch"
    )
    if (
        type(contract["version"]) is not int
        or contract
        != {
            "id": PWN_INTERACTION_PRODUCER_CONTRACT_ID,
            "protocol": PWN_INTERACTION_PRODUCER_PROTOCOL,
            "recipe_contract_fingerprint": (
                PWN_INTERACTION_V1_CONTRACT_FINGERPRINT
            ),
            "version": PWN_INTERACTION_PRODUCER_CONTRACT_VERSION,
        }
    ):
        _fail("producer_contract_mismatch")
    binding = _exact(
        root["binding"], _BINDING_KEYS, "producer_binding_invalid"
    )
    expected_document_binding = {
        "configuration_epoch": expected_binding.configuration_epoch,
        "image_digest": expected_binding.image_digest,
        "network": "none",
        "ordinal": expected_ordinal,
        "phase": expected_phase,
        "preissue_sha256": expected_binding.preissue_sha256,
        "producer_sha256": expected_binding.producer_sha256,
        "recipe_sha256": expected_binding.recipe_sha256,
        "recipe_size_bytes": expected_binding.recipe_size_bytes,
        "source_manifest_sha256": (
            expected_binding.source_manifest_sha256
        ),
        "source_sha256": expected_binding.source_sha256,
        "source_size_bytes": expected_binding.source_size_bytes,
    }
    if (
        type(binding["configuration_epoch"]) is not int
        or type(binding["ordinal"]) is not int
        or type(binding["recipe_size_bytes"]) is not int
        or type(binding["source_size_bytes"]) is not int
        or binding != expected_document_binding
    ):
        _fail("producer_binding_mismatch")
    status = root["status"]
    reason = root["reason_code"]
    if (
        status not in {"effect_absent", "effect_observed", "unverifiable"}
        or type(reason) is not str
        or _SAFE_REASON.fullmatch(reason) is None
    ):
        _fail("producer_status_invalid")
    if root["observation"] is not None:
        _exact(
            root["observation"],
            _OBSERVATION_KEYS,
            "producer_observation_schema_invalid",
        )
    elif status != "unverifiable":
        _fail("producer_observation_missing")
    return root


def _literal(value: object) -> bytes:
    if type(value) is not dict or frozenset(value) != {
        "encoding",
        "value",
    }:
        _fail("recipe_runtime_invalid")
    encoding = value["encoding"]
    text = value["value"]
    if type(text) is not str:
        _fail("recipe_runtime_invalid")
    try:
        return (
            bytes.fromhex(text)
            if encoding == "hex"
            else text.encode("utf-8")
        )
    except (UnicodeError, ValueError):
        _fail("recipe_runtime_invalid")


def _validate_attached_artifact(
    observation: Mapping[str, object],
    *,
    name: str,
    payload: bytes,
    maximum: int,
    expected_path: str,
) -> None:
    if type(payload) is not bytes or len(payload) > maximum:
        _fail(f"{name}_artifact_invalid")
    if observation[f"{name}_path"] != expected_path:
        _fail(f"{name}_path_mismatch")
    if (
        type(observation[f"{name}_size_bytes"]) is not int
        or observation[f"{name}_sha256"] != _sha256(payload)
        or observation[f"{name}_size_bytes"] != len(payload)
    ):
        _fail(f"{name}_artifact_mismatch")


def _validate_transcript(
    payload: bytes,
    *,
    phase: str,
    ordinal: int,
    recipe_sha256: str,
    stdout: bytes,
    stderr: bytes,
) -> tuple[tuple[bytes, int], ...]:
    root = _exact(
        _parse_canonical(
            payload,
            PWN_INTERACTION_MAX_TRANSCRIPT_BYTES,
            "transcript_invalid",
        ),
        _TRANSCRIPT_KEYS,
        "transcript_schema_invalid",
    )
    if type(root["schema_version"]) is not int or root["schema_version"] != 1:
        _fail("transcript_schema_invalid")
    binding = _exact(
        root["binding"],
        _TRANSCRIPT_BINDING_KEYS,
        "transcript_binding_invalid",
    )
    if (
        type(binding["ordinal"]) is not int
        or binding
        != {
            "ordinal": ordinal,
            "phase": phase,
            "recipe_sha256": recipe_sha256,
        }
    ):
        _fail("transcript_binding_mismatch")
    events = root["events"]
    if type(events) is not list or len(events) > 262_144:
        _fail("transcript_events_invalid")
    reconstructed = {
        "stdin": bytearray(),
        "stdout": bytearray(),
        "stderr": bytearray(),
    }
    sends: list[tuple[bytes, int]] = []
    for sequence, item in enumerate(events, start=1):
        event = _exact(item, _EVENT_KEYS, "transcript_event_invalid")
        if (
            type(event["sequence"]) is not int
            or event["sequence"] != sequence
        ):
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
            or len(encoded) > 131_072
        ):
            _fail("transcript_data_invalid")
        try:
            chunk = bytes.fromhex(encoded)
        except ValueError:
            _fail("transcript_data_invalid")
        if not chunk or len(chunk) > PWN_INTERACTION_V1_MAX_SEND_BYTES:
            _fail("transcript_chunk_invalid")
        current = reconstructed[stream]
        if (
            type(event["offset"]) is not int
            or type(event["size_bytes"]) is not int
            or event["offset"] != len(current)
            or event["size_bytes"] != len(chunk)
            or event["sha256"] != _sha256(chunk)
        ):
            _fail("transcript_event_mismatch")
        current.extend(chunk)
        if direction == "send":
            sends.append((chunk, len(reconstructed["stdout"])))
    if (
        bytes(reconstructed["stdout"]) != stdout
        or bytes(reconstructed["stderr"]) != stderr
        or len(reconstructed["stdin"])
        > PWN_INTERACTION_V1_MAX_AGGREGATE_SEND_BYTES
    ):
        _fail("transcript_stream_mismatch")
    return tuple(sends)


def _validate_dag_and_recipe(
    payload: bytes,
    *,
    phase: str,
    ordinal: int,
    recipe_sha256: str,
    recipe: Mapping[str, object],
    stdout: bytes,
    sends: tuple[tuple[bytes, int], ...],
) -> None:
    root = _exact(
        _parse_canonical(
            payload,
            PWN_INTERACTION_MAX_DAG_BYTES,
            "derivation_dag_invalid",
        ),
        _DAG_KEYS,
        "derivation_dag_schema_invalid",
    )
    if type(root["schema_version"]) is not int or root["schema_version"] != 1:
        _fail("derivation_dag_schema_invalid")
    binding = _exact(
        root["binding"],
        _TRANSCRIPT_BINDING_KEYS,
        "derivation_dag_binding_invalid",
    )
    if (
        type(binding["ordinal"]) is not int
        or binding
        != {
            "ordinal": ordinal,
            "phase": phase,
            "recipe_sha256": recipe_sha256,
        }
    ):
        _fail("derivation_dag_binding_mismatch")
    nodes = root["nodes"]
    if type(nodes) is not list or len(nodes) > 128:
        _fail("derivation_dag_nodes_invalid")

    node_cursor = 0
    send_cursor = 0
    stdout_cursor = 0
    values: dict[str, tuple[str, int | bytes, frozenset[str]]] = {
        PWN_INTERACTION_V1_SENTINEL_REF: (
            "bytes",
            PWN_INTERACTION_SENTINEL_COMMAND,
            frozenset({PWN_INTERACTION_V1_SENTINEL_REF}),
        )
    }
    seen_names: set[str] = set()
    effect_ref = str(recipe["effect"]["address_ref"])
    substituted = 0

    def operand(raw: object) -> tuple[int, str | None]:
        if type(raw) is not dict:
            _fail("recipe_runtime_invalid")
        if frozenset(raw) == {"value"} and type(raw["value"]) is int:
            return raw["value"], None
        if frozenset(raw) != {"ref"} or raw["ref"] not in values:
            _fail("recipe_runtime_invalid")
        kind, value, _dependencies = values[str(raw["ref"])]
        if kind != "u64" or type(value) is not int:
            _fail("recipe_runtime_invalid")
        return value, str(raw["ref"])

    def part(raw: object) -> tuple[bytes, str | None]:
        if type(raw) is not dict:
            _fail("recipe_runtime_invalid")
        if frozenset(raw) == {"literal"}:
            return _literal(raw["literal"]), None
        if frozenset(raw) != {"ref"} or raw["ref"] not in values:
            _fail("recipe_runtime_invalid")
        kind, value, _dependencies = values[str(raw["ref"])]
        if kind != "bytes" or type(value) is not bytes:
            _fail("recipe_runtime_invalid")
        return value, str(raw["ref"])

    def define(
        item: Mapping[str, object],
        kind: str,
        value: int | bytes,
        references: tuple[str, ...] = (),
    ) -> None:
        nonlocal node_cursor, substituted
        if node_cursor >= len(nodes):
            _fail("derivation_dag_node_missing")
        name = item["name"]
        if (
            type(name) is not str
            or _SAFE_NAME.fullmatch(name) is None
            or name in seen_names
        ):
            _fail("derivation_dag_name_invalid")
        seen_names.add(name)
        expected_substitution = phase == "control" and name == effect_ref
        if expected_substitution:
            value = 0
            substituted += 1
        elif name == effect_ref and (type(value) is not int or value == 0):
            _fail("effect_value_invalid")
        dependencies = {name}
        for reference in references:
            dependencies.update(values[reference][2])
        encoded = (
            struct.pack("<Q", value)
            if kind == "u64" and type(value) is int
            else bytes(value)
        )
        node = _exact(
            nodes[node_cursor],
            (
                _NODE_BASE_KEYS | {"u64"}
                if kind == "u64"
                else _NODE_BASE_KEYS
            ),
            "derivation_dag_node_invalid",
        )
        node_cursor += 1
        if (
            node["name"] != name
            or node["op"] != item["op"]
            or node["step_id"] != item["id"]
            or node["type"] != kind
            or node["control_substituted"] is not expected_substitution
            or node["dependencies"] != sorted(dependencies)
            or type(node["size_bytes"]) is not int
            or node["size_bytes"] != len(encoded)
            or node["sha256"] != _sha256(encoded)
            or (
                kind == "u64"
                and (
                    type(node["u64"]) is not int
                    or node["u64"] != value
                )
            )
        ):
            _fail("derivation_dag_node_mismatch")
        if expected_substitution:
            if kind != "u64":
                _fail("effect_value_invalid")
        values[name] = (kind, value, frozenset(dependencies))

    steps = recipe["steps"]
    if type(steps) is not list:
        _fail("recipe_runtime_invalid")
    for item in steps:
        if type(item) is not dict:
            _fail("recipe_runtime_invalid")
        op = item["op"]
        if op == "expect_exact":
            expected = _literal(item["data"])
            index = stdout.find(expected, stdout_cursor)
            if index < 0 or index + len(expected) - stdout_cursor > item[
                "max_read_bytes"
            ]:
                _fail("recipe_observation_mismatch")
            stdout_cursor = index + len(expected)
        elif op == "expect_safe_regex":
            newline = stdout.find(b"\n", stdout_cursor)
            if newline < 0:
                _fail("recipe_observation_mismatch")
            try:
                pattern = re.compile(str(item["pattern"]).encode("ascii"))
            except (UnicodeError, re.error):
                _fail("recipe_runtime_invalid")
            if (
                pattern.fullmatch(stdout[stdout_cursor:newline]) is None
                or newline + 1 - stdout_cursor > item["max_read_bytes"]
            ):
                _fail("recipe_observation_mismatch")
            stdout_cursor = newline + 1
        elif op == "capture_hex":
            prefix = _literal(item["prefix"])
            index = stdout.find(prefix, stdout_cursor)
            if index < 0:
                _fail("recipe_observation_mismatch")
            start = index + len(prefix)
            end = start
            while (
                end < len(stdout)
                and end - start < 16
                and stdout[end] in b"0123456789abcdefABCDEF"
            ):
                end += 1
            if (
                end == start
                or end - stdout_cursor > item["max_read_bytes"]
                or (
                    end - start == 16
                    and end < len(stdout)
                    and stdout[end] in b"0123456789abcdefABCDEF"
                )
            ):
                _fail("recipe_observation_mismatch")
            define(item, "u64", int(stdout[start:end], 16))
            stdout_cursor = end
        elif op == "capture_u64_line":
            newline = stdout.find(b"\n", stdout_cursor)
            raw = stdout[stdout_cursor:newline] if newline >= 0 else b""
            if (
                newline < 0
                or not 1 <= len(raw) <= 8
                or newline + 1 - stdout_cursor > item["max_read_bytes"]
            ):
                _fail("recipe_observation_mismatch")
            define(
                item,
                "u64",
                int.from_bytes(raw.ljust(8, b"\0"), "little"),
            )
            stdout_cursor = newline + 1
        elif op == "set_u64":
            define(item, "u64", int(item["value"]))
        elif op == "derive_u64":
            left, left_ref = operand(item["left"])
            right, right_ref = operand(item["right"])
            operator = item["operator"]
            if operator == "add":
                value = left + right
                if value > _U64_MAX:
                    _fail("recipe_runtime_invalid")
            elif operator == "sub":
                if left < right:
                    _fail("recipe_runtime_invalid")
                value = left - right
            elif operator == "and":
                value = left & right
            elif operator == "or":
                value = left | right
            elif operator == "xor":
                value = left ^ right
            else:
                _fail("recipe_runtime_invalid")
            define(
                item,
                "u64",
                value,
                tuple(
                    ref
                    for ref in (left_ref, right_ref)
                    if ref is not None
                ),
            )
        elif op == "assert_u64":
            left, _ = operand(item["left"])
            right, _ = operand(item["right"])
            comparison = item["comparison"]
            passed = {
                "eq": left == right,
                "ne": left != right,
                "lt": left < right,
                "le": left <= right,
                "gt": left > right,
                "ge": left >= right,
                "aligned": right != 0 and left % right == 0,
            }.get(comparison, False)
            if not passed:
                _fail("recipe_observation_mismatch")
        elif op == "literal":
            define(item, "bytes", _literal(item["data"]))
        elif op == "pack_u64":
            value, reference = operand(item["value"])
            define(
                item,
                "bytes",
                struct.pack("<Q", value),
                () if reference is None else (reference,),
            )
        elif op == "concat":
            chunks: list[bytes] = []
            references: list[str] = []
            for raw in item["parts"]:
                chunk, reference = part(raw)
                chunks.append(chunk)
                if reference is not None:
                    references.append(reference)
            define(item, "bytes", b"".join(chunks), tuple(references))
        elif op == "send":
            chunks = [part(raw)[0] for raw in item["parts"]]
            expected = b"".join(chunks)
            if item["mode"] == "line":
                expected += b"\n"
            if (
                send_cursor >= len(sends)
                or sends[send_cursor][0] != expected
                or stdout_cursor > sends[send_cursor][1]
            ):
                _fail("transcript_send_mismatch")
            send_cursor += 1
        elif op in {"delay", "shutdown_stdin"}:
            continue
        else:
            _fail("recipe_runtime_invalid")
    if (
        node_cursor != len(nodes)
        or send_cursor != len(sends)
        or substituted != (1 if phase == "control" else 0)
    ):
        _fail("derivation_dag_completeness_invalid")


def _validate_replay(
    evidence: PwnInteractionReplayEvidence,
    *,
    expected_binding: PwnInteractionExpectedBinding,
    phase: str,
    ordinal: int,
    recipe: Mapping[str, object],
) -> PwnInteractionReplayReceipt:
    if type(evidence) is not PwnInteractionReplayEvidence:
        _fail("replay_evidence_invalid")
    root = parse_pwn_interaction_producer_document(
        evidence.document_bytes,
        expected_binding=expected_binding,
        expected_phase=phase,
        expected_ordinal=ordinal,
    )
    observation = root["observation"]
    if type(observation) is not dict:
        _fail("producer_observation_missing")
    base = (
        f".ctf/pwn-interaction-v1/{expected_binding.recipe_sha256}/"
        f"{phase}-{ordinal}"
    )
    _validate_attached_artifact(
        observation,
        name="stdout",
        payload=evidence.stdout_bytes,
        maximum=PWN_INTERACTION_MAX_STREAM_BYTES,
        expected_path=f"{base}/target.stdout.bin",
    )
    _validate_attached_artifact(
        observation,
        name="stderr",
        payload=evidence.stderr_bytes,
        maximum=PWN_INTERACTION_MAX_STREAM_BYTES,
        expected_path=f"{base}/target.stderr.bin",
    )
    _validate_attached_artifact(
        observation,
        name="transcript",
        payload=evidence.transcript_bytes,
        maximum=PWN_INTERACTION_MAX_TRANSCRIPT_BYTES,
        expected_path=f"{base}/transcript.json",
    )
    _validate_attached_artifact(
        observation,
        name="derivation_dag",
        payload=evidence.derivation_dag_bytes,
        maximum=PWN_INTERACTION_MAX_DAG_BYTES,
        expected_path=f"{base}/derivation-dag.json",
    )
    if (
        observation["timed_out"] is not False
        or observation["process_group_cleaned"] is not True
        or type(observation["control_substitution_applied"]) is not bool
    ):
        _fail("process_completion_invalid")
    _integer(
        observation["elapsed_milliseconds"],
        0,
        PWN_INTERACTION_V1_MAX_TIMEOUT_MILLISECONDS + 5_000,
        "elapsed_time_invalid",
    )
    exit_code = observation["target_exit_code"]
    target_signal = observation["target_signal"]
    if (
        (exit_code is None) == (target_signal is None)
        or (
            exit_code is not None
            and (
                type(exit_code) is not int
                or not 0 <= exit_code <= 255
            )
        )
        or (
            target_signal is not None
            and (
                type(target_signal) is not int
                or not 1 <= target_signal <= 64
            )
        )
    ):
        _fail("terminal_metadata_invalid")
    sends = _validate_transcript(
        evidence.transcript_bytes,
        phase=phase,
        ordinal=ordinal,
        recipe_sha256=expected_binding.recipe_sha256,
        stdout=evidence.stdout_bytes,
        stderr=evidence.stderr_bytes,
    )
    _validate_dag_and_recipe(
        evidence.derivation_dag_bytes,
        phase=phase,
        ordinal=ordinal,
        recipe_sha256=expected_binding.recipe_sha256,
        recipe=recipe,
        stdout=evidence.stdout_bytes,
        sends=sends,
    )
    combined = evidence.stdout_bytes + evidence.stderr_bytes
    shaped = _SENTINEL.findall(combined)
    prefix_count = combined.count(_SENTINEL_PREFIX)
    sentinel_count = _integer(
        observation["sentinel_occurrences"],
        0,
        1,
        "sentinel_count_invalid",
    )
    sentinel_sha256 = _hash(
        observation["sentinel_sha256"], "sentinel_hash_invalid"
    )
    expected_positive = phase == "attack"
    if expected_positive:
        if (
            root["status"] != "effect_observed"
            or root["reason_code"] != "unpredictable_sentinel_emitted"
            or sentinel_count != 1
            or len(shaped) != 1
            or prefix_count != 1
            or _sha256(shaped[0]) != sentinel_sha256
            or observation["control_substitution_applied"] is not False
        ):
            _fail("positive_observation_invalid")
    elif (
        root["status"] != "effect_absent"
        or root["reason_code"] != "sentinel_not_emitted"
        or sentinel_count != 0
        or shaped
        or prefix_count
        or observation["control_substitution_applied"] is not True
    ):
        _fail("negative_control_invalid")
    return PwnInteractionReplayReceipt(
        phase=phase,
        ordinal=ordinal,
        status=str(root["status"]),
        reason_code=str(root["reason_code"]),
        sentinel_sha256=sentinel_sha256,
        stdout_sha256=_sha256(evidence.stdout_bytes),
        stderr_sha256=_sha256(evidence.stderr_bytes),
        transcript_sha256=_sha256(evidence.transcript_bytes),
        derivation_dag_sha256=_sha256(
            evidence.derivation_dag_bytes
        ),
        target_exit_code=exit_code,
        target_signal=target_signal,
        control_substitution_applied=observation[
            "control_substitution_applied"
        ],
    )


def evaluate_pwn_interaction_replays(
    evidence: Iterable[PwnInteractionReplayEvidence],
    *,
    expected_binding: PwnInteractionExpectedBinding,
    recipe_bytes: bytes,
) -> PwnInteractionEvaluation:
    """Validate and evaluate exactly three positives and three controls."""

    _validate_expected_binding(expected_binding)
    if (
        type(recipe_bytes) is not bytes
        or len(recipe_bytes) != expected_binding.recipe_size_bytes
        or _sha256(recipe_bytes) != expected_binding.recipe_sha256
    ):
        _fail("recipe_binding_mismatch")
    try:
        parsed_recipe = parse_pwn_interaction_v1_recipe(recipe_bytes)
    except ValueError as error:
        raise PwnInteractionEvaluationError(
            "recipe_contract_invalid"
        ) from error
    try:
        items = tuple(evidence)
    except (TypeError, RuntimeError) as error:
        raise PwnInteractionEvaluationError(
            "replay_evidence_invalid"
        ) from error
    if len(items) != PWN_INTERACTION_RUNS_PER_PHASE * 2:
        _fail("replay_count_mismatch")
    attacks: list[PwnInteractionReplayReceipt] = []
    controls: list[PwnInteractionReplayReceipt] = []
    for index, item in enumerate(items):
        phase = "attack" if index < 3 else "control"
        ordinal = index + 1 if phase == "attack" else index - 2
        receipt = _validate_replay(
            item,
            expected_binding=expected_binding,
            phase=phase,
            ordinal=ordinal,
            recipe=parsed_recipe.document,
        )
        (attacks if phase == "attack" else controls).append(receipt)
    sentinel_hashes = {
        receipt.sentinel_sha256 for receipt in (*attacks, *controls)
    }
    if len(sentinel_hashes) != 6:
        _fail("sentinel_reused")
    terminals = {
        (receipt.target_exit_code, receipt.target_signal)
        for receipt in (*attacks, *controls)
    }
    if len(terminals) != 1:
        _fail("terminal_metadata_mismatch")
    return PwnInteractionEvaluation(
        passed=True,
        reason_code="validated_three_positive_three_control_replays",
        attack_receipts=tuple(attacks),
        control_receipts=tuple(controls),
    )


__all__ = [
    "PWN_INTERACTION_MAX_DAG_BYTES",
    "PWN_INTERACTION_MAX_DOCUMENT_BYTES",
    "PWN_INTERACTION_MAX_STREAM_BYTES",
    "PWN_INTERACTION_MAX_TRANSCRIPT_BYTES",
    "PWN_INTERACTION_PRODUCER_CONTRACT_ID",
    "PWN_INTERACTION_PRODUCER_CONTRACT_VERSION",
    "PWN_INTERACTION_PRODUCER_PROTOCOL",
    "PWN_INTERACTION_RUNS_PER_PHASE",
    "PwnInteractionEvaluation",
    "PwnInteractionEvaluationError",
    "PwnInteractionExpectedBinding",
    "PwnInteractionReplayEvidence",
    "PwnInteractionReplayReceipt",
    "evaluate_pwn_interaction_replays",
    "parse_pwn_interaction_producer_document",
]
