"""Pure contract for bounded, data-only local Pwn interaction recipes.

The recipe is intentionally not a program.  It cannot name an interpreter,
shell, command, environment variable, filesystem destination, or network
target.  A pinned image producer may interpret the closed operation set
against one engine-selected local ELF.  The producer owns the unpredictable
sentinel and the attack/control phase; the recipe author cannot choose either.

This module performs no process execution.  It validates canonical JSON,
closed schemas, typed data-flow, bounded reads/writes/delays, and the required
effect dependency.  Runtime transcript and 3-positive/3-control evaluation
belong to the image producer and engine gate.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from ctf_os.contracts.interaction_data_common import (
    canonical_ascii_json_bytes,
    translate_common_error,
)


PWN_INTERACTION_V1_SCHEMA_VERSION = 1
PWN_INTERACTION_V1_CONTRACT_ID = "ctfos.pwn.interaction_recipe"
PWN_INTERACTION_V1_CONTRACT_VERSION = 1
PWN_INTERACTION_V1_PROTOCOL = "pwn_local_bounded_interaction_v1"
PWN_INTERACTION_V1_MAX_DOCUMENT_BYTES = 256 * 1024
PWN_INTERACTION_V1_MAX_JSON_DEPTH = 12
PWN_INTERACTION_V1_MAX_STEPS = 128
PWN_INTERACTION_V1_MAX_CAPTURES = 32
PWN_INTERACTION_V1_MAX_STEP_READ_BYTES = 1024 * 1024
PWN_INTERACTION_V1_MAX_SEND_BYTES = 64 * 1024
PWN_INTERACTION_V1_MAX_AGGREGATE_SEND_BYTES = 1024 * 1024
PWN_INTERACTION_V1_MAX_TIMEOUT_MILLISECONDS = 120_000
PWN_INTERACTION_V1_MAX_DELAY_MILLISECONDS = 500
PWN_INTERACTION_V1_MAX_AGGREGATE_DELAY_MILLISECONDS = 5_000
PWN_INTERACTION_V1_MAX_VALUE_BYTES = 64 * 1024
PWN_INTERACTION_V1_MAX_PARTS = 64
PWN_INTERACTION_V1_MAX_SAFE_REGEX_BYTES = 256
PWN_INTERACTION_V1_SENTINEL_REF = "sentinel_command"
PWN_INTERACTION_V1_SENTINEL_PREFIX = "CTFOS_PWN_INTERACTION_V1_"

_ROOT_KEYS = frozenset(
    {"contract", "effect", "schema_version", "steps", "timeout_milliseconds"}
)
_CONTRACT_KEYS = frozenset({"id", "protocol", "version"})
_EFFECT_KEYS = frozenset(
    {"address_ref", "control_value", "sentinel_ref", "success_stream"}
)
_SAFE_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SAFE_STEP_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_SAFE_HEX = re.compile(r"^(?:[0-9a-f]{2})*$")
_SAFE_REGEX_CHARACTER = re.compile(r"^[\x20-\x7e]+$")
_BOUNDED_QUANTIFIER = re.compile(r"\{([0-9]{1,3})(?:,([0-9]{1,3}))?\}")
_U64_MAX = (1 << 64) - 1
_CLOSED_OPS = frozenset(
    {
        "assert_u64",
        "capture_hex",
        "capture_u64_line",
        "concat",
        "delay",
        "derive_u64",
        "expect_exact",
        "expect_safe_regex",
        "literal",
        "pack_u64",
        "send",
        "set_u64",
        "shutdown_stdin",
    }
)


class PwnInteractionRecipeError(ValueError):
    """A stable fail-closed recipe validation error."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class PwnInteractionRecipe:
    """Validated canonical recipe and static execution accounting."""

    document: Mapping[str, object]
    canonical_bytes: bytes
    sha256: str
    step_count: int
    capture_count: int
    maximum_aggregate_send_bytes: int
    aggregate_delay_milliseconds: int
    effect_address_ref: str
    effect_payload_refs: tuple[str, ...]


def pwn_interaction_v1_canonical_json_bytes(value: object) -> bytes:
    """Return the sole accepted JSON representation."""

    return translate_common_error(
        lambda: canonical_ascii_json_bytes(value),
        lambda _error: PwnInteractionRecipeError(
            "invalid_json_value",
            "recipe contains a value outside canonical ASCII JSON",
        ),
    )


def _reject_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PwnInteractionRecipeError(
                "duplicate_json_key",
                f"duplicate object key {key!r}",
            )
        result[key] = value
    return result


def _json_depth(value: object, *, depth: int = 1) -> int:
    if depth > PWN_INTERACTION_V1_MAX_JSON_DEPTH:
        return depth
    if type(value) is dict:
        return max(
            (depth, *(_json_depth(item, depth=depth + 1) for item in value.values()))
        )
    if type(value) is list:
        return max(
            (depth, *(_json_depth(item, depth=depth + 1) for item in value))
        )
    return depth


def _mapping(
    value: object,
    *,
    keys: frozenset[str],
    label: str,
) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != keys:
        raise PwnInteractionRecipeError(
            "invalid_schema",
            f"{label} must contain exactly {sorted(keys)}",
        )
    return value


def _integer(
    value: object,
    *,
    minimum: int,
    maximum: int,
    label: str,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise PwnInteractionRecipeError(
            "invalid_schema",
            f"{label} must be an integer in {minimum}..{maximum}",
        )
    return value


def _name(value: object, *, label: str) -> str:
    if type(value) is not str or _SAFE_NAME.fullmatch(value) is None:
        raise PwnInteractionRecipeError(
            "invalid_schema",
            f"{label} is not a safe identifier",
        )
    if value == PWN_INTERACTION_V1_SENTINEL_REF:
        raise PwnInteractionRecipeError(
            "reserved_name",
            f"{label} cannot replace the producer-owned sentinel",
        )
    return value


def _step_id(value: object) -> str:
    if type(value) is not str or _SAFE_STEP_ID.fullmatch(value) is None:
        raise PwnInteractionRecipeError(
            "invalid_schema",
            "step id is not a safe identifier",
        )
    return value


def _literal_bytes(value: object, *, label: str) -> bytes:
    raw = _mapping(
        value,
        keys=frozenset({"encoding", "value"}),
        label=label,
    )
    encoding = raw["encoding"]
    encoded = raw["value"]
    if type(encoded) is not str or encoding not in {"hex", "utf8"}:
        raise PwnInteractionRecipeError(
            "invalid_schema",
            f"{label} requires encoding hex or utf8 and a string value",
        )
    if encoding == "hex":
        if _SAFE_HEX.fullmatch(encoded) is None:
            raise PwnInteractionRecipeError(
                "invalid_schema",
                f"{label} is not lowercase even-length hexadecimal",
            )
        result = bytes.fromhex(encoded)
    else:
        try:
            result = encoded.encode("utf-8")
        except UnicodeEncodeError as error:
            raise PwnInteractionRecipeError(
                "invalid_schema",
                f"{label} is not valid UTF-8 text",
            ) from error
    if len(result) > PWN_INTERACTION_V1_MAX_VALUE_BYTES:
        raise PwnInteractionRecipeError(
            "value_too_large",
            f"{label} exceeds the per-value byte bound",
        )
    if PWN_INTERACTION_V1_SENTINEL_PREFIX.encode("ascii") in result:
        raise PwnInteractionRecipeError(
            "sentinel_shape_forbidden",
            f"{label} contains the producer-owned sentinel prefix",
        )
    return result


def _safe_regex(value: object) -> str:
    if type(value) is not str:
        raise PwnInteractionRecipeError(
            "invalid_schema",
            "safe regex must be a string",
        )
    try:
        size = len(value.encode("ascii"))
    except UnicodeEncodeError as error:
        raise PwnInteractionRecipeError(
            "unsafe_regex",
            "safe regex must be printable ASCII",
        ) from error
    if (
        not 3 <= size <= PWN_INTERACTION_V1_MAX_SAFE_REGEX_BYTES
        or _SAFE_REGEX_CHARACTER.fullmatch(value) is None
        or not value.startswith("^")
        or not value.endswith("$")
        or any(token in value for token in ("(", ")", "|", "\\", "*", "+"))
        or PWN_INTERACTION_V1_SENTINEL_PREFIX in value
    ):
        raise PwnInteractionRecipeError(
            "unsafe_regex",
            "regex must be anchored, printable, group-free, and bounded",
        )
    scrubbed = _BOUNDED_QUANTIFIER.sub("", value)
    if "{" in scrubbed or "}" in scrubbed:
        raise PwnInteractionRecipeError(
            "unsafe_regex",
            "regex contains an invalid bounded quantifier",
        )
    for match in _BOUNDED_QUANTIFIER.finditer(value):
        lower = int(match.group(1))
        upper = int(match.group(2) or match.group(1))
        if lower > upper or upper > 256:
            raise PwnInteractionRecipeError(
                "unsafe_regex",
                "regex quantifier exceeds the deterministic bound",
            )
    try:
        re.compile(value.encode("ascii"))
    except re.error as error:
        raise PwnInteractionRecipeError(
            "unsafe_regex",
            "regex does not compile",
        ) from error
    return value


def _u64_operand(
    value: object,
    *,
    known_types: Mapping[str, str],
    label: str,
) -> tuple[str | None, int | None]:
    raw = _mapping(
        value,
        keys=(
            frozenset({"ref"})
            if type(value) is dict and frozenset(value) == {"ref"}
            else frozenset({"value"})
        ),
        label=label,
    )
    if "ref" in raw:
        reference = raw["ref"]
        if (
            type(reference) is not str
            or known_types.get(reference) != "u64"
        ):
            raise PwnInteractionRecipeError(
                "unknown_or_mistyped_reference",
                f"{label} must reference a previously defined u64",
            )
        return reference, None
    return None, _integer(
        raw["value"],
        minimum=0,
        maximum=_U64_MAX,
        label=f"{label}.value",
    )


def _bytes_part(
    value: object,
    *,
    known_types: Mapping[str, str],
    known_max_bytes: Mapping[str, int],
    label: str,
) -> tuple[str | None, int]:
    if type(value) is not dict:
        raise PwnInteractionRecipeError(
            "invalid_schema",
            f"{label} must be an object",
        )
    if frozenset(value) == {"ref"}:
        reference = value["ref"]
        if (
            type(reference) is not str
            or known_types.get(reference) != "bytes"
        ):
            raise PwnInteractionRecipeError(
                "unknown_or_mistyped_reference",
                f"{label} must reference previously defined bytes",
            )
        return reference, known_max_bytes[reference]
    if frozenset(value) == {"literal"}:
        return None, len(_literal_bytes(value["literal"], label=f"{label}.literal"))
    raise PwnInteractionRecipeError(
        "invalid_schema",
        f"{label} must contain exactly ref or literal",
    )


def _transitive_dependencies(
    reference: str,
    dependencies: Mapping[str, frozenset[str]],
) -> frozenset[str]:
    return dependencies.get(reference, frozenset({reference}))


def parse_pwn_interaction_v1_recipe(
    payload: bytes,
) -> PwnInteractionRecipe:
    """Parse and fully validate one canonical recipe."""

    if type(payload) is not bytes:
        raise PwnInteractionRecipeError(
            "invalid_transport",
            "recipe payload must be exact bytes",
        )
    if not payload or len(payload) > PWN_INTERACTION_V1_MAX_DOCUMENT_BYTES:
        raise PwnInteractionRecipeError(
            "artifact_too_large",
            "recipe is empty or exceeds the document bound",
        )
    try:
        value = json.loads(
            payload.decode("ascii"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda token: (_ for _ in ()).throw(
                PwnInteractionRecipeError(
                    "invalid_json",
                    f"non-finite JSON token {token!r}",
                )
            ),
        )
    except PwnInteractionRecipeError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PwnInteractionRecipeError(
            "invalid_json",
            "recipe is not strict ASCII JSON",
        ) from error
    if _json_depth(value) > PWN_INTERACTION_V1_MAX_JSON_DEPTH:
        raise PwnInteractionRecipeError(
            "json_too_deep",
            "recipe exceeds the JSON nesting bound",
        )
    canonical = pwn_interaction_v1_canonical_json_bytes(value)
    if payload != canonical:
        raise PwnInteractionRecipeError(
            "noncanonical_json",
            "recipe is not canonical JSON",
        )
    root = _mapping(value, keys=_ROOT_KEYS, label="recipe")
    if root["schema_version"] != PWN_INTERACTION_V1_SCHEMA_VERSION:
        raise PwnInteractionRecipeError(
            "contract_mismatch",
            "unsupported recipe schema version",
        )
    contract = _mapping(
        root["contract"],
        keys=_CONTRACT_KEYS,
        label="contract",
    )
    if contract != {
        "id": PWN_INTERACTION_V1_CONTRACT_ID,
        "protocol": PWN_INTERACTION_V1_PROTOCOL,
        "version": PWN_INTERACTION_V1_CONTRACT_VERSION,
    }:
        raise PwnInteractionRecipeError(
            "contract_mismatch",
            "recipe contract tuple does not match v1",
        )
    _integer(
        root["timeout_milliseconds"],
        minimum=1,
        maximum=PWN_INTERACTION_V1_MAX_TIMEOUT_MILLISECONDS,
        label="timeout_milliseconds",
    )
    effect = _mapping(
        root["effect"],
        keys=_EFFECT_KEYS,
        label="effect",
    )
    address_ref = _name(effect["address_ref"], label="effect.address_ref")
    if (
        effect["control_value"] != 0
        or effect["sentinel_ref"] != PWN_INTERACTION_V1_SENTINEL_REF
        or effect["success_stream"] != "stdout_or_stderr"
    ):
        raise PwnInteractionRecipeError(
            "invalid_effect_contract",
            "control, sentinel, and success stream are producer-owned",
        )
    steps = root["steps"]
    if (
        type(steps) is not list
        or not 1 <= len(steps) <= PWN_INTERACTION_V1_MAX_STEPS
    ):
        raise PwnInteractionRecipeError(
            "invalid_schema",
            "steps must be a non-empty bounded array",
        )

    known_types: dict[str, str] = {
        PWN_INTERACTION_V1_SENTINEL_REF: "bytes"
    }
    known_max_bytes: dict[str, int] = {
        PWN_INTERACTION_V1_SENTINEL_REF: 256
    }
    dependencies: dict[str, frozenset[str]] = {
        PWN_INTERACTION_V1_SENTINEL_REF: frozenset(
            {PWN_INTERACTION_V1_SENTINEL_REF}
        )
    }
    step_ids: set[str] = set()
    capture_count = 0
    aggregate_send = 0
    aggregate_delay = 0
    effect_payload_refs: list[str] = []
    sentinel_sent = False
    stdin_shutdown = False

    def define(
        raw_name: object,
        value_type: str,
        *,
        maximum_bytes: int = 0,
        depends_on: Sequence[str] = (),
    ) -> str:
        name = _name(raw_name, label="step.name")
        if name in known_types:
            raise PwnInteractionRecipeError(
                "duplicate_name",
                f"value name {name!r} is already defined",
            )
        known_types[name] = value_type
        if value_type == "bytes":
            known_max_bytes[name] = maximum_bytes
        expanded = {name}
        for reference in depends_on:
            expanded.update(_transitive_dependencies(reference, dependencies))
        dependencies[name] = frozenset(expanded)
        return name

    for ordinal, item in enumerate(steps, start=1):
        if type(item) is not dict:
            raise PwnInteractionRecipeError(
                "invalid_schema",
                f"step {ordinal} is not an object",
            )
        if "id" not in item or "op" not in item:
            raise PwnInteractionRecipeError(
                "invalid_schema",
                f"step {ordinal} lacks id or op",
            )
        current_id = _step_id(item["id"])
        if current_id in step_ids:
            raise PwnInteractionRecipeError(
                "duplicate_step_id",
                f"step id {current_id!r} is duplicated",
            )
        step_ids.add(current_id)
        op = item["op"]
        if type(op) is not str or op not in _CLOSED_OPS:
            raise PwnInteractionRecipeError(
                "unknown_operation",
                f"step {current_id!r} uses an unsupported operation",
            )
        if stdin_shutdown:
            raise PwnInteractionRecipeError(
                "step_after_shutdown",
                "no interaction step may follow shutdown_stdin",
            )

        if op == "expect_exact":
            raw = _mapping(
                item,
                keys=frozenset({"data", "id", "max_read_bytes", "op"}),
                label=f"step {current_id}",
            )
            expected = _literal_bytes(raw["data"], label="expect_exact.data")
            if not expected:
                raise PwnInteractionRecipeError(
                    "invalid_schema",
                    "expect_exact data cannot be empty",
                )
            _integer(
                raw["max_read_bytes"],
                minimum=len(expected),
                maximum=PWN_INTERACTION_V1_MAX_STEP_READ_BYTES,
                label="expect_exact.max_read_bytes",
            )
            continue

        if op == "expect_safe_regex":
            raw = _mapping(
                item,
                keys=frozenset({"id", "max_read_bytes", "op", "pattern"}),
                label=f"step {current_id}",
            )
            _safe_regex(raw["pattern"])
            _integer(
                raw["max_read_bytes"],
                minimum=1,
                maximum=PWN_INTERACTION_V1_MAX_STEP_READ_BYTES,
                label="expect_safe_regex.max_read_bytes",
            )
            continue

        if op in {"capture_hex", "capture_u64_line"}:
            raw = _mapping(
                item,
                keys=(
                    frozenset({"id", "max_read_bytes", "name", "op", "prefix"})
                    if op == "capture_hex"
                    else frozenset({"id", "max_read_bytes", "name", "op"})
                ),
                label=f"step {current_id}",
            )
            if op == "capture_hex":
                prefix = _literal_bytes(
                    raw["prefix"],
                    label="capture_hex.prefix",
                )
                if not prefix:
                    raise PwnInteractionRecipeError(
                        "invalid_schema",
                        "capture_hex prefix cannot be empty",
                    )
            _integer(
                raw["max_read_bytes"],
                minimum=1,
                maximum=PWN_INTERACTION_V1_MAX_STEP_READ_BYTES,
                label=f"{op}.max_read_bytes",
            )
            define(raw["name"], "u64")
            capture_count += 1
            if capture_count > PWN_INTERACTION_V1_MAX_CAPTURES:
                raise PwnInteractionRecipeError(
                    "capture_limit_exceeded",
                    "recipe defines too many dynamic captures",
                )
            continue

        if op == "set_u64":
            raw = _mapping(
                item,
                keys=frozenset({"id", "name", "op", "value"}),
                label=f"step {current_id}",
            )
            _integer(
                raw["value"],
                minimum=0,
                maximum=_U64_MAX,
                label="set_u64.value",
            )
            define(raw["name"], "u64")
            continue

        if op == "derive_u64":
            raw = _mapping(
                item,
                keys=frozenset(
                    {"id", "left", "name", "op", "operator", "right"}
                ),
                label=f"step {current_id}",
            )
            if raw["operator"] not in {"add", "and", "or", "sub", "xor"}:
                raise PwnInteractionRecipeError(
                    "invalid_schema",
                    "derive_u64 operator is not in the closed checked set",
                )
            left_ref, _ = _u64_operand(
                raw["left"],
                known_types=known_types,
                label="derive_u64.left",
            )
            right_ref, _ = _u64_operand(
                raw["right"],
                known_types=known_types,
                label="derive_u64.right",
            )
            define(
                raw["name"],
                "u64",
                depends_on=tuple(
                    reference
                    for reference in (left_ref, right_ref)
                    if reference is not None
                ),
            )
            continue

        if op == "assert_u64":
            raw = _mapping(
                item,
                keys=frozenset(
                    {"comparison", "id", "left", "op", "right"}
                ),
                label=f"step {current_id}",
            )
            if raw["comparison"] not in {
                "aligned",
                "eq",
                "ge",
                "gt",
                "le",
                "lt",
                "ne",
            }:
                raise PwnInteractionRecipeError(
                    "invalid_schema",
                    "assert_u64 comparison is not in the closed set",
                )
            _u64_operand(
                raw["left"],
                known_types=known_types,
                label="assert_u64.left",
            )
            _u64_operand(
                raw["right"],
                known_types=known_types,
                label="assert_u64.right",
            )
            continue

        if op == "literal":
            raw = _mapping(
                item,
                keys=frozenset({"data", "id", "name", "op"}),
                label=f"step {current_id}",
            )
            value_bytes = _literal_bytes(raw["data"], label="literal.data")
            define(raw["name"], "bytes", maximum_bytes=len(value_bytes))
            continue

        if op == "pack_u64":
            raw = _mapping(
                item,
                keys=frozenset({"id", "name", "op", "value"}),
                label=f"step {current_id}",
            )
            reference, _ = _u64_operand(
                raw["value"],
                known_types=known_types,
                label="pack_u64.value",
            )
            define(
                raw["name"],
                "bytes",
                maximum_bytes=8,
                depends_on=(() if reference is None else (reference,)),
            )
            continue

        if op == "concat":
            raw = _mapping(
                item,
                keys=frozenset({"id", "name", "op", "parts"}),
                label=f"step {current_id}",
            )
            parts = raw["parts"]
            if (
                type(parts) is not list
                or not 1 <= len(parts) <= PWN_INTERACTION_V1_MAX_PARTS
            ):
                raise PwnInteractionRecipeError(
                    "invalid_schema",
                    "concat parts must be a non-empty bounded array",
                )
            refs: list[str] = []
            maximum = 0
            for part_index, part in enumerate(parts):
                reference, part_maximum = _bytes_part(
                    part,
                    known_types=known_types,
                    known_max_bytes=known_max_bytes,
                    label=f"concat.parts[{part_index}]",
                )
                maximum += part_maximum
                if reference is not None:
                    refs.append(reference)
            if maximum > PWN_INTERACTION_V1_MAX_SEND_BYTES:
                raise PwnInteractionRecipeError(
                    "value_too_large",
                    "concat can exceed the per-send byte bound",
                )
            define(
                raw["name"],
                "bytes",
                maximum_bytes=maximum,
                depends_on=refs,
            )
            continue

        if op == "send":
            raw = _mapping(
                item,
                keys=frozenset({"id", "mode", "op", "parts"}),
                label=f"step {current_id}",
            )
            if raw["mode"] not in {"line", "raw"}:
                raise PwnInteractionRecipeError(
                    "invalid_schema",
                    "send mode must be line or raw",
                )
            parts = raw["parts"]
            if (
                type(parts) is not list
                or not 1 <= len(parts) <= PWN_INTERACTION_V1_MAX_PARTS
            ):
                raise PwnInteractionRecipeError(
                    "invalid_schema",
                    "send parts must be a non-empty bounded array",
                )
            maximum = 1 if raw["mode"] == "line" else 0
            send_dependencies: set[str] = set()
            for part_index, part in enumerate(parts):
                reference, part_maximum = _bytes_part(
                    part,
                    known_types=known_types,
                    known_max_bytes=known_max_bytes,
                    label=f"send.parts[{part_index}]",
                )
                maximum += part_maximum
                if reference is not None:
                    send_dependencies.update(
                        _transitive_dependencies(reference, dependencies)
                    )
            if maximum > PWN_INTERACTION_V1_MAX_SEND_BYTES:
                raise PwnInteractionRecipeError(
                    "send_limit_exceeded",
                    "one send can exceed the per-send byte bound",
                )
            aggregate_send += maximum
            if aggregate_send > PWN_INTERACTION_V1_MAX_AGGREGATE_SEND_BYTES:
                raise PwnInteractionRecipeError(
                    "send_limit_exceeded",
                    "recipe can exceed the aggregate send bound",
                )
            if address_ref in send_dependencies:
                effect_payload_refs.extend(sorted(send_dependencies))
            if PWN_INTERACTION_V1_SENTINEL_REF in send_dependencies:
                sentinel_sent = True
            continue

        if op == "delay":
            raw = _mapping(
                item,
                keys=frozenset({"id", "milliseconds", "op"}),
                label=f"step {current_id}",
            )
            aggregate_delay += _integer(
                raw["milliseconds"],
                minimum=0,
                maximum=PWN_INTERACTION_V1_MAX_DELAY_MILLISECONDS,
                label="delay.milliseconds",
            )
            if (
                aggregate_delay
                > PWN_INTERACTION_V1_MAX_AGGREGATE_DELAY_MILLISECONDS
            ):
                raise PwnInteractionRecipeError(
                    "delay_limit_exceeded",
                    "recipe exceeds the aggregate delay bound",
                )
            continue

        if op == "shutdown_stdin":
            _mapping(
                item,
                keys=frozenset({"id", "op"}),
                label=f"step {current_id}",
            )
            stdin_shutdown = True
            continue

        raise AssertionError(f"unhandled closed operation {op}")

    if known_types.get(address_ref) != "u64":
        raise PwnInteractionRecipeError(
            "effect_reference_invalid",
            "effect address must name a prior u64 value",
        )
    if not effect_payload_refs:
        raise PwnInteractionRecipeError(
            "effect_reference_unused",
            "effect address does not reach any transmitted bytes",
        )
    if not sentinel_sent:
        raise PwnInteractionRecipeError(
            "sentinel_reference_unused",
            "producer-owned sentinel command is never transmitted",
        )
    return PwnInteractionRecipe(
        document=value,
        canonical_bytes=canonical,
        sha256=hashlib.sha256(canonical).hexdigest(),
        step_count=len(steps),
        capture_count=capture_count,
        maximum_aggregate_send_bytes=aggregate_send,
        aggregate_delay_milliseconds=aggregate_delay,
        effect_address_ref=address_ref,
        effect_payload_refs=tuple(sorted(set(effect_payload_refs))),
    )


def pwn_interaction_v1_contract_descriptor() -> dict[str, object]:
    """Expose the immutable limits consumed by host/image drift tests."""

    return {
        "contract_id": PWN_INTERACTION_V1_CONTRACT_ID,
        "contract_version": PWN_INTERACTION_V1_CONTRACT_VERSION,
        "protocol": PWN_INTERACTION_V1_PROTOCOL,
        "schema_version": PWN_INTERACTION_V1_SCHEMA_VERSION,
        "operations": sorted(_CLOSED_OPS),
        "limits": {
            "aggregate_delay_milliseconds": (
                PWN_INTERACTION_V1_MAX_AGGREGATE_DELAY_MILLISECONDS
            ),
            "aggregate_send_bytes": (
                PWN_INTERACTION_V1_MAX_AGGREGATE_SEND_BYTES
            ),
            "captures": PWN_INTERACTION_V1_MAX_CAPTURES,
            "delay_milliseconds": PWN_INTERACTION_V1_MAX_DELAY_MILLISECONDS,
            "document_bytes": PWN_INTERACTION_V1_MAX_DOCUMENT_BYTES,
            "safe_regex_bytes": PWN_INTERACTION_V1_MAX_SAFE_REGEX_BYTES,
            "send_bytes": PWN_INTERACTION_V1_MAX_SEND_BYTES,
            "step_read_bytes": PWN_INTERACTION_V1_MAX_STEP_READ_BYTES,
            "steps": PWN_INTERACTION_V1_MAX_STEPS,
            "timeout_milliseconds": (
                PWN_INTERACTION_V1_MAX_TIMEOUT_MILLISECONDS
            ),
        },
        "phase_authority": "image_producer",
        "sentinel_authority": "image_producer",
        "sentinel_ref": PWN_INTERACTION_V1_SENTINEL_REF,
        "transport": "canonical-ascii-json-newline-v1",
    }


PWN_INTERACTION_V1_CONTRACT_FINGERPRINT = hashlib.sha256(
    pwn_interaction_v1_canonical_json_bytes(
        pwn_interaction_v1_contract_descriptor()
    )
).hexdigest()


__all__ = [
    "PWN_INTERACTION_V1_CONTRACT_FINGERPRINT",
    "PWN_INTERACTION_V1_CONTRACT_ID",
    "PWN_INTERACTION_V1_CONTRACT_VERSION",
    "PWN_INTERACTION_V1_MAX_AGGREGATE_DELAY_MILLISECONDS",
    "PWN_INTERACTION_V1_MAX_AGGREGATE_SEND_BYTES",
    "PWN_INTERACTION_V1_MAX_CAPTURES",
    "PWN_INTERACTION_V1_MAX_DELAY_MILLISECONDS",
    "PWN_INTERACTION_V1_MAX_DOCUMENT_BYTES",
    "PWN_INTERACTION_V1_MAX_SEND_BYTES",
    "PWN_INTERACTION_V1_MAX_STEP_READ_BYTES",
    "PWN_INTERACTION_V1_MAX_STEPS",
    "PWN_INTERACTION_V1_MAX_TIMEOUT_MILLISECONDS",
    "PWN_INTERACTION_V1_PROTOCOL",
    "PWN_INTERACTION_V1_SCHEMA_VERSION",
    "PWN_INTERACTION_V1_SENTINEL_REF",
    "PwnInteractionRecipe",
    "PwnInteractionRecipeError",
    "parse_pwn_interaction_v1_recipe",
    "pwn_interaction_v1_canonical_json_bytes",
    "pwn_interaction_v1_contract_descriptor",
]
