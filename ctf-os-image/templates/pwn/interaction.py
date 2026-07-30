#!/usr/bin/env python3
"""Execute one bounded, data-only Pwn interaction recipe.

The target is one descriptor-bound local ELF.  This producer never accepts a
shell, interpreter, environment, argv extension, harness, or network target.
It validates the closed v1 recipe again inside the pinned image, creates the
unpredictable sentinel only after the recipe and source are immutable, and
interprets the recipe against the ELF with bounded pipes.

Stdout is reserved for one canonical result document.  Raw target streams,
the interaction transcript, and the derivation DAG are immutable bounded
files below ``/work/.ctf/pwn-interaction-v1``.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import resource
import select
import secrets
import signal
import stat
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Mapping, Sequence


CHALLENGE_ROOT = Path("/challenge")
WORK_ROOT = Path("/work")
OUTPUT_ROOT_RELATIVE = Path(".ctf/pwn-interaction-v1")
SENTINEL_PATH_RELATIVE = Path("ctfos-pwn-interaction-sentinel-v1")

SCHEMA_VERSION = 1
CONTRACT_ID = "ctfos.pwn.interaction_recipe"
CONTRACT_VERSION = 1
PROTOCOL = "pwn_local_bounded_interaction_v1"
PRODUCER_CONTRACT_ID = "ctfos.pwn.interaction"
PRODUCER_CONTRACT_VERSION = 1
PRODUCER_PROTOCOL = "pwn_local_bounded_interaction_producer_v1"
CONTRACT_FINGERPRINT = (
    "5f8df2cf3cbaa9dc897d6a7c46c677c5fa3578f5369e9de5052bfe9acae3c9f3"
)

MAX_SOURCE_BYTES = 1024 * 1024 * 1024
MAX_RECIPE_BYTES = 256 * 1024
MAX_JSON_DEPTH = 12
MAX_STEPS = 128
MAX_CAPTURES = 32
MAX_STEP_READ_BYTES = 1024 * 1024
MAX_SEND_BYTES = 64 * 1024
MAX_AGGREGATE_SEND_BYTES = 1024 * 1024
MAX_TIMEOUT_MILLISECONDS = 120_000
MAX_DELAY_MILLISECONDS = 500
MAX_AGGREGATE_DELAY_MILLISECONDS = 5_000
MAX_VALUE_BYTES = 64 * 1024
MAX_PARTS = 64
MAX_SAFE_REGEX_BYTES = 256
MAX_STREAM_BYTES = 1024 * 1024
MAX_TRANSCRIPT_BYTES = 8 * 1024 * 1024
MAX_DAG_BYTES = 1024 * 1024
MAX_DOCUMENT_BYTES = 64 * 1024
MAX_DESCENDANT_PROCESSES = 4096

SENTINEL_REF = "sentinel_command"
SENTINEL_PREFIX = b"CTFOS_PWN_INTERACTION_V1_"
SENTINEL_RE = re.compile(
    rb"CTFOS_PWN_INTERACTION_V1_[0-9a-f]{64}\n"
)
SENTINEL_COMMAND = (
    b"cat /work/ctfos-pwn-interaction-sentinel-v1\0"
)
FIXED_ENVIRONMENT = {
    "HOME": "/nonexistent",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/bin:/bin",
    "TERM": "dumb",
}

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
_BOUNDED_QUANTIFIER = re.compile(
    r"\{([0-9]{1,3})(?:,([0-9]{1,3}))?\}"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
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
_PR_GET_DUMPABLE = 3
_PR_SET_DUMPABLE = 4
_PR_GET_NO_NEW_PRIVS = 39
_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_CHILD_SUBREAPER = 36
_PR_GET_CHILD_SUBREAPER = 37


class ProducerError(RuntimeError):
    """Fail closed with one stable, non-secret reason code."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


def _canonical_json_bytes(value: object) -> bytes:
    try:
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
    except (TypeError, UnicodeError, ValueError) as error:
        raise ProducerError("canonical_json_invalid") from error


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _strict_positive_int(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected decimal integer") from error
    if parsed <= 0:
        raise argparse.ArgumentTypeError("expected positive integer")
    return parsed


def _configuration_epoch(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected decimal integer") from error
    if not 0 <= parsed <= (1 << 63) - 1:
        raise argparse.ArgumentTypeError("invalid configuration epoch")
    return parsed


def _sha256_argument(value: str) -> str:
    if _SHA256.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("expected lowercase SHA-256")
    return value


def _image_digest_argument(value: str) -> str:
    if _IMAGE_DIGEST.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("expected sha256 image digest")
    return value


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the bounded Pwn interaction producer.",
    )
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--recipe", type=Path, required=True)
    parser.add_argument(
        "--phase",
        choices=("attack", "control"),
        required=True,
    )
    parser.add_argument(
        "--ordinal",
        type=_strict_positive_int,
        required=True,
    )
    parser.add_argument(
        "--source-manifest-sha256",
        type=_sha256_argument,
        required=True,
    )
    parser.add_argument(
        "--source-sha256",
        type=_sha256_argument,
        required=True,
    )
    parser.add_argument(
        "--source-size-bytes",
        type=_strict_positive_int,
        required=True,
    )
    parser.add_argument(
        "--recipe-sha256",
        type=_sha256_argument,
        required=True,
    )
    parser.add_argument(
        "--recipe-size-bytes",
        type=_strict_positive_int,
        required=True,
    )
    parser.add_argument(
        "--image-digest",
        type=_image_digest_argument,
        required=True,
    )
    parser.add_argument(
        "--configuration-epoch",
        type=_configuration_epoch,
        required=True,
    )
    parser.add_argument(
        "--preissue-sha256",
        type=_sha256_argument,
        required=True,
    )
    return parser.parse_args(argv)


def _json_depth(value: object, depth: int = 1) -> int:
    if depth > MAX_JSON_DEPTH:
        return depth
    if type(value) is dict:
        return max(
            [depth]
            + [_json_depth(item, depth + 1) for item in value.values()]
        )
    if type(value) is list:
        return max(
            [depth] + [_json_depth(item, depth + 1) for item in value]
        )
    return depth


def _duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProducerError("recipe_duplicate_json_key")
        result[key] = value
    return result


def _mapping(
    value: object,
    keys: frozenset[str],
) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != keys:
        raise ProducerError("recipe_invalid_schema")
    return value


def _integer(
    value: object,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ProducerError("recipe_invalid_schema")
    return value


def _name(value: object) -> str:
    if (
        type(value) is not str
        or _SAFE_NAME.fullmatch(value) is None
        or value == SENTINEL_REF
    ):
        raise ProducerError("recipe_invalid_schema")
    return value


def _literal_bytes(value: object) -> bytes:
    raw = _mapping(value, frozenset({"encoding", "value"}))
    encoding = raw["encoding"]
    encoded = raw["value"]
    if type(encoded) is not str or encoding not in {"hex", "utf8"}:
        raise ProducerError("recipe_invalid_schema")
    try:
        if encoding == "hex":
            if _SAFE_HEX.fullmatch(encoded) is None:
                raise ProducerError("recipe_invalid_schema")
            result = bytes.fromhex(encoded)
        else:
            result = encoded.encode("utf-8")
    except (UnicodeError, ValueError) as error:
        raise ProducerError("recipe_invalid_schema") from error
    if (
        len(result) > MAX_VALUE_BYTES
        or SENTINEL_PREFIX in result
    ):
        raise ProducerError("recipe_value_invalid")
    return result


def _safe_regex(value: object) -> bytes:
    if type(value) is not str:
        raise ProducerError("recipe_unsafe_regex")
    try:
        encoded = value.encode("ascii")
    except UnicodeError as error:
        raise ProducerError("recipe_unsafe_regex") from error
    if (
        not 3 <= len(encoded) <= MAX_SAFE_REGEX_BYTES
        or _SAFE_REGEX_CHARACTER.fullmatch(value) is None
        or not value.startswith("^")
        or not value.endswith("$")
        or any(token in value for token in ("(", ")", "|", "\\", "*", "+"))
        or SENTINEL_PREFIX.decode("ascii") in value
    ):
        raise ProducerError("recipe_unsafe_regex")
    scrubbed = _BOUNDED_QUANTIFIER.sub("", value)
    if "{" in scrubbed or "}" in scrubbed:
        raise ProducerError("recipe_unsafe_regex")
    for match in _BOUNDED_QUANTIFIER.finditer(value):
        lower = int(match.group(1))
        upper = int(match.group(2) or match.group(1))
        if lower > upper or upper > 256:
            raise ProducerError("recipe_unsafe_regex")
    try:
        re.compile(encoded)
    except re.error as error:
        raise ProducerError("recipe_unsafe_regex") from error
    return encoded


def _u64_operand_schema(
    value: object,
    known_types: Mapping[str, str],
) -> str | None:
    if type(value) is not dict:
        raise ProducerError("recipe_invalid_schema")
    if frozenset(value) == {"ref"}:
        reference = value["ref"]
        if type(reference) is not str or known_types.get(reference) != "u64":
            raise ProducerError("recipe_reference_invalid")
        return reference
    if frozenset(value) == {"value"}:
        _integer(value["value"], 0, _U64_MAX)
        return None
    raise ProducerError("recipe_invalid_schema")


def _bytes_part_schema(
    value: object,
    known_types: Mapping[str, str],
    known_max_bytes: Mapping[str, int],
) -> tuple[str | None, int]:
    if type(value) is not dict:
        raise ProducerError("recipe_invalid_schema")
    if frozenset(value) == {"ref"}:
        reference = value["ref"]
        if type(reference) is not str or known_types.get(reference) != "bytes":
            raise ProducerError("recipe_reference_invalid")
        return reference, known_max_bytes[reference]
    if frozenset(value) == {"literal"}:
        return None, len(_literal_bytes(value["literal"]))
    raise ProducerError("recipe_invalid_schema")


def _parse_recipe(payload: bytes) -> dict[str, object]:
    """Validate the same closed recipe grammar inside the image."""

    if not payload or len(payload) > MAX_RECIPE_BYTES:
        raise ProducerError("recipe_size_invalid")
    try:
        value = json.loads(
            payload.decode("ascii"),
            object_pairs_hook=_duplicate_keys,
            parse_constant=lambda _token: (_ for _ in ()).throw(
                ProducerError("recipe_invalid_json")
            ),
        )
    except ProducerError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ProducerError("recipe_invalid_json") from error
    if _json_depth(value) > MAX_JSON_DEPTH:
        raise ProducerError("recipe_json_too_deep")
    if _canonical_json_bytes(value) != payload:
        raise ProducerError("recipe_noncanonical")
    root = _mapping(value, _ROOT_KEYS)
    contract = _mapping(root["contract"], _CONTRACT_KEYS)
    if (
        root["schema_version"] != SCHEMA_VERSION
        or contract
        != {
            "id": CONTRACT_ID,
            "protocol": PROTOCOL,
            "version": CONTRACT_VERSION,
        }
    ):
        raise ProducerError("recipe_contract_mismatch")
    _integer(root["timeout_milliseconds"], 1, MAX_TIMEOUT_MILLISECONDS)
    effect = _mapping(root["effect"], _EFFECT_KEYS)
    address_ref = _name(effect["address_ref"])
    if effect != {
        "address_ref": address_ref,
        "control_value": 0,
        "sentinel_ref": SENTINEL_REF,
        "success_stream": "stdout_or_stderr",
    }:
        raise ProducerError("recipe_effect_invalid")
    steps = root["steps"]
    if type(steps) is not list or not 1 <= len(steps) <= MAX_STEPS:
        raise ProducerError("recipe_steps_invalid")

    known_types: dict[str, str] = {SENTINEL_REF: "bytes"}
    # The host contract intentionally budgets a fixed 256-byte producer
    # value, not this implementation's current shorter command.
    known_max: dict[str, int] = {SENTINEL_REF: 256}
    dependencies: dict[str, frozenset[str]] = {
        SENTINEL_REF: frozenset({SENTINEL_REF})
    }
    step_ids: set[str] = set()
    captures = 0
    aggregate_send = 0
    aggregate_delay = 0
    effect_reaches_send = False
    sentinel_reaches_send = False
    shutdown = False

    def define(
        raw_name: object,
        value_type: str,
        *,
        maximum: int = 0,
        refs: Sequence[str] = (),
    ) -> str:
        name = _name(raw_name)
        if name in known_types:
            raise ProducerError("recipe_duplicate_name")
        known_types[name] = value_type
        if value_type == "bytes":
            known_max[name] = maximum
        expanded = {name}
        for reference in refs:
            expanded.update(dependencies[reference])
        dependencies[name] = frozenset(expanded)
        return name

    for item in steps:
        if type(item) is not dict or "id" not in item or "op" not in item:
            raise ProducerError("recipe_invalid_schema")
        step_id = item["id"]
        if (
            type(step_id) is not str
            or _SAFE_STEP_ID.fullmatch(step_id) is None
            or step_id in step_ids
        ):
            raise ProducerError("recipe_step_id_invalid")
        step_ids.add(step_id)
        op = item["op"]
        if type(op) is not str or op not in _CLOSED_OPS:
            raise ProducerError("recipe_operation_invalid")
        if shutdown:
            raise ProducerError("recipe_step_after_shutdown")

        if op == "expect_exact":
            raw = _mapping(
                item, frozenset({"data", "id", "max_read_bytes", "op"})
            )
            data = _literal_bytes(raw["data"])
            if not data:
                raise ProducerError("recipe_invalid_schema")
            _integer(raw["max_read_bytes"], len(data), MAX_STEP_READ_BYTES)
        elif op == "expect_safe_regex":
            raw = _mapping(
                item,
                frozenset({"id", "max_read_bytes", "op", "pattern"}),
            )
            _safe_regex(raw["pattern"])
            _integer(raw["max_read_bytes"], 1, MAX_STEP_READ_BYTES)
        elif op in {"capture_hex", "capture_u64_line"}:
            raw = _mapping(
                item,
                (
                    frozenset(
                        {"id", "max_read_bytes", "name", "op", "prefix"}
                    )
                    if op == "capture_hex"
                    else frozenset({"id", "max_read_bytes", "name", "op"})
                ),
            )
            if op == "capture_hex" and not _literal_bytes(raw["prefix"]):
                raise ProducerError("recipe_invalid_schema")
            _integer(raw["max_read_bytes"], 1, MAX_STEP_READ_BYTES)
            define(raw["name"], "u64")
            captures += 1
            if captures > MAX_CAPTURES:
                raise ProducerError("recipe_capture_limit_exceeded")
        elif op == "set_u64":
            raw = _mapping(
                item, frozenset({"id", "name", "op", "value"})
            )
            _integer(raw["value"], 0, _U64_MAX)
            define(raw["name"], "u64")
        elif op == "derive_u64":
            raw = _mapping(
                item,
                frozenset(
                    {"id", "left", "name", "op", "operator", "right"}
                ),
            )
            if raw["operator"] not in {"add", "and", "or", "sub", "xor"}:
                raise ProducerError("recipe_invalid_schema")
            refs = [
                ref
                for ref in (
                    _u64_operand_schema(raw["left"], known_types),
                    _u64_operand_schema(raw["right"], known_types),
                )
                if ref is not None
            ]
            define(raw["name"], "u64", refs=refs)
        elif op == "assert_u64":
            raw = _mapping(
                item,
                frozenset(
                    {"comparison", "id", "left", "op", "right"}
                ),
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
                raise ProducerError("recipe_invalid_schema")
            _u64_operand_schema(raw["left"], known_types)
            _u64_operand_schema(raw["right"], known_types)
        elif op == "literal":
            raw = _mapping(
                item, frozenset({"data", "id", "name", "op"})
            )
            data = _literal_bytes(raw["data"])
            define(raw["name"], "bytes", maximum=len(data))
        elif op == "pack_u64":
            raw = _mapping(
                item, frozenset({"id", "name", "op", "value"})
            )
            ref = _u64_operand_schema(raw["value"], known_types)
            define(
                raw["name"],
                "bytes",
                maximum=8,
                refs=(() if ref is None else (ref,)),
            )
        elif op == "concat":
            raw = _mapping(
                item, frozenset({"id", "name", "op", "parts"})
            )
            parts = raw["parts"]
            if type(parts) is not list or not 1 <= len(parts) <= MAX_PARTS:
                raise ProducerError("recipe_invalid_schema")
            maximum = 0
            refs: list[str] = []
            for part in parts:
                ref, size = _bytes_part_schema(part, known_types, known_max)
                maximum += size
                if ref is not None:
                    refs.append(ref)
            if maximum > MAX_SEND_BYTES:
                raise ProducerError("recipe_value_limit_exceeded")
            define(raw["name"], "bytes", maximum=maximum, refs=refs)
        elif op == "send":
            raw = _mapping(
                item, frozenset({"id", "mode", "op", "parts"})
            )
            if raw["mode"] not in {"line", "raw"}:
                raise ProducerError("recipe_invalid_schema")
            parts = raw["parts"]
            if type(parts) is not list or not 1 <= len(parts) <= MAX_PARTS:
                raise ProducerError("recipe_invalid_schema")
            maximum = 1 if raw["mode"] == "line" else 0
            send_deps: set[str] = set()
            for part in parts:
                ref, size = _bytes_part_schema(part, known_types, known_max)
                maximum += size
                if ref is not None:
                    send_deps.update(dependencies[ref])
            if maximum > MAX_SEND_BYTES:
                raise ProducerError("recipe_send_limit_exceeded")
            aggregate_send += maximum
            if aggregate_send > MAX_AGGREGATE_SEND_BYTES:
                raise ProducerError("recipe_send_limit_exceeded")
            effect_reaches_send |= address_ref in send_deps
            sentinel_reaches_send |= SENTINEL_REF in send_deps
        elif op == "delay":
            raw = _mapping(
                item, frozenset({"id", "milliseconds", "op"})
            )
            aggregate_delay += _integer(
                raw["milliseconds"], 0, MAX_DELAY_MILLISECONDS
            )
            if aggregate_delay > MAX_AGGREGATE_DELAY_MILLISECONDS:
                raise ProducerError("recipe_delay_limit_exceeded")
        elif op == "shutdown_stdin":
            _mapping(item, frozenset({"id", "op"}))
            shutdown = True
        else:
            raise AssertionError("closed operation dispatch drift")
    if known_types.get(address_ref) != "u64" or not effect_reaches_send:
        raise ProducerError("recipe_effect_reference_invalid")
    if not sentinel_reaches_send:
        raise ProducerError("recipe_sentinel_reference_invalid")
    return value


def _read_regular_exact(
    path: Path,
    *,
    root: Path,
    expected_sha256: str,
    expected_size: int,
    maximum_bytes: int,
    executable: bool,
    retain: bool,
) -> tuple[int, bytes]:
    try:
        canonical_root = root.resolve(strict=True)
        canonical_parent = path.parent.resolve(strict=True)
    except OSError as error:
        raise ProducerError("artifact_parent_unavailable") from error
    if canonical_parent != canonical_root and canonical_root not in (
        canonical_parent.parents
    ):
        raise ProducerError("artifact_outside_root")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ProducerError("artifact_open_failed") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ProducerError("artifact_not_regular")
        if executable and (
            before.st_mode & (stat.S_ISUID | stat.S_ISGID)
            or before.st_mode & 0o111 == 0
        ):
            raise ProducerError("binary_mode_invalid")
        if before.st_size != expected_size or before.st_size > maximum_bytes:
            raise ProducerError("artifact_size_mismatch")
        digest = hashlib.sha256()
        content = bytearray()
        prefix = bytearray()
        total = 0
        while total <= maximum_bytes:
            chunk = os.read(
                descriptor,
                min(65536, maximum_bytes + 1 - total),
            )
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
            if len(prefix) < 4:
                prefix.extend(chunk[: 4 - len(prefix)])
            if retain:
                content.extend(chunk)
        after = os.fstat(descriptor)
        stable = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_uid",
            "st_gid",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(
            getattr(before, field) != getattr(after, field)
            for field in stable
        ):
            raise ProducerError("artifact_changed_during_read")
        if total != expected_size or digest.hexdigest() != expected_sha256:
            raise ProducerError("artifact_hash_mismatch")
        if executable and bytes(prefix) != b"\x7fELF":
            raise ProducerError("binary_not_elf")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor, bytes(content)
    except BaseException:
        os.close(descriptor)
        raise


def _protect_producer() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    libc.prctl.restype = ctypes.c_int
    if (
        libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) != 0
        or libc.prctl(_PR_GET_DUMPABLE, 0, 0, 0, 0) != 0
        or libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
        or libc.prctl(_PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1
    ):
        raise ProducerError("producer_process_protection_unavailable")
    subreaper = ctypes.c_int(0)
    if (
        libc.prctl(_PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0
        or libc.prctl(
            _PR_GET_CHILD_SUBREAPER,
            ctypes.addressof(subreaper),
            0,
            0,
            0,
        )
        != 0
        or subreaper.value != 1
    ):
        raise ProducerError("producer_process_protection_unavailable")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _child_limits() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(
        resource.RLIMIT_FSIZE,
        (MAX_STREAM_BYTES, MAX_STREAM_BYTES),
    )
    os.umask(0o077)


def _ensure_output_directory(
    recipe_sha256: str,
    phase: str,
    ordinal: int,
) -> Path:
    current = WORK_ROOT
    for component in OUTPUT_ROOT_RELATIVE.parts:
        current = current / component
        try:
            current.mkdir(mode=0o700)
        except FileExistsError:
            pass
        info = os.lstat(current)
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise ProducerError("output_directory_unsafe")
        current.chmod(0o700)
    plan = current / recipe_sha256
    attempt = plan / f"{phase}-{ordinal}"
    for path in (plan, attempt):
        try:
            path.mkdir(mode=0o700)
        except FileExistsError as error:
            raise ProducerError("output_directory_preexisting") from error
        info = os.lstat(path)
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise ProducerError("output_directory_unsafe")
    return attempt


def _write_immutable(path: Path, payload: bytes, maximum: int) -> None:
    if len(payload) > maximum:
        raise ProducerError("evidence_size_limit_exceeded")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags, 0o400)
    except OSError as error:
        raise ProducerError("evidence_create_failed") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ProducerError("evidence_file_unsafe")
        view = memoryview(payload)
        written = 0
        while written < len(payload):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise ProducerError("evidence_write_failed")
            written += count
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
    finally:
        os.close(descriptor)


def _self_sha256() -> str:
    try:
        payload = Path(__file__).read_bytes()
    except OSError as error:
        raise ProducerError("producer_attestation_unavailable") from error
    return _sha256(payload)


def _process_parent_snapshot() -> dict[int, int]:
    parents: dict[int, int] = {}
    try:
        entries = tuple(Path("/proc").iterdir())
    except OSError as error:
        raise ProducerError("process_tree_inspection_failed") from error
    if len(entries) > MAX_DESCENDANT_PROCESSES * 4:
        raise ProducerError("process_tree_limit_exceeded")
    for entry in entries:
        if not entry.name.isdecimal():
            continue
        try:
            raw = (entry / "stat").read_bytes()
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError as error:
            raise ProducerError("process_tree_inspection_failed") from error
        if len(raw) > 4096:
            raise ProducerError("process_tree_inspection_failed")
        marker = raw.rfind(b") ")
        fields = raw[marker + 2 :].split() if marker >= 0 else []
        if len(fields) < 2:
            raise ProducerError("process_tree_inspection_failed")
        try:
            parents[int(entry.name)] = int(fields[1], 10)
        except ValueError as error:
            raise ProducerError("process_tree_inspection_failed") from error
    return parents


def _descendant_pids(root_pid: int) -> tuple[int, ...]:
    parents = _process_parent_snapshot()
    descendants: set[int] = set()
    changed = True
    while changed:
        changed = False
        for pid, parent in parents.items():
            if (
                pid != root_pid
                and pid not in descendants
                and (parent == root_pid or parent in descendants)
            ):
                descendants.add(pid)
                changed = True
                if len(descendants) > MAX_DESCENDANT_PROCESSES:
                    raise ProducerError("process_tree_limit_exceeded")
    return tuple(sorted(descendants, reverse=True))


def _reap_children() -> None:
    while True:
        try:
            waited, _status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        except InterruptedError:
            continue
        if waited == 0:
            return


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> bool:
    clean = True
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        clean = False
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        clean = False
    deadline = time.monotonic() + 2
    empty = 0
    while time.monotonic() < deadline:
        try:
            descendants = _descendant_pids(os.getpid())
        except ProducerError:
            return False
        for pid in descendants:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                clean = False
        _reap_children()
        try:
            remaining = _descendant_pids(os.getpid())
        except ProducerError:
            return False
        if not remaining:
            empty += 1
            if empty >= 2:
                return clean
        else:
            empty = 0
        time.sleep(0.01)
    return False


class _Runtime:
    """One finite recipe interpreter over an already-started target."""

    def __init__(
        self,
        process: subprocess.Popen[bytes],
        recipe: Mapping[str, object],
        *,
        phase: str,
        started: float,
    ) -> None:
        if process.stdin is None or process.stdout is None or process.stderr is None:
            raise ProducerError("target_pipe_unavailable")
        self.process = process
        self.recipe = recipe
        self.phase = phase
        self.started = started
        self.deadline = started + (
            int(recipe["timeout_milliseconds"]) / 1000
        )
        self.stdin = process.stdin
        self.stdout_fd = process.stdout.fileno()
        self.stderr_fd = process.stderr.fileno()
        self.stdin_fd = process.stdin.fileno()
        os.set_blocking(self.stdout_fd, False)
        os.set_blocking(self.stderr_fd, False)
        os.set_blocking(self.stdin_fd, False)
        self.streams = {
            "stdout": bytearray(),
            "stderr": bytearray(),
        }
        self.open_streams = {"stdout", "stderr"}
        self.stdout_cursor = 0
        self.values: dict[str, tuple[str, int | bytes, frozenset[str]]] = {
            SENTINEL_REF: (
                "bytes",
                SENTINEL_COMMAND,
                frozenset({SENTINEL_REF}),
            )
        }
        self.transcript: list[dict[str, object]] = []
        self.dag: list[dict[str, object]] = []
        self.sequence = 0
        self.total_sent = 0
        self.effect_ref = str(
            _mapping(recipe["effect"], _EFFECT_KEYS)["address_ref"]
        )
        self.effect_substituted = False

    def _remaining(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ProducerError("target_timeout")
        return remaining

    def _record(
        self,
        direction: str,
        stream: str,
        payload: bytes,
        offset: int,
    ) -> None:
        self.sequence += 1
        self.transcript.append(
            {
                "data_hex": payload.hex(),
                "direction": direction,
                "offset": offset,
                "sequence": self.sequence,
                "sha256": _sha256(payload),
                "size_bytes": len(payload),
                "stream": stream,
            }
        )

    def _read_ready(self, timeout: float) -> None:
        descriptors = [
            (
                self.stdout_fd
                if stream == "stdout"
                else self.stderr_fd
            )
            for stream in sorted(self.open_streams)
        ]
        if not descriptors:
            if timeout:
                time.sleep(min(timeout, self._remaining()))
            return
        try:
            ready, _writable, _errors = select.select(
                descriptors,
                [],
                [],
                min(timeout, self._remaining()),
            )
        except (OSError, ValueError) as error:
            raise ProducerError("target_pipe_read_failed") from error
        for descriptor in ready:
            stream = "stdout" if descriptor == self.stdout_fd else "stderr"
            try:
                chunk = os.read(descriptor, 65536)
            except BlockingIOError:
                continue
            except OSError as error:
                raise ProducerError("target_pipe_read_failed") from error
            if not chunk:
                self.open_streams.discard(stream)
                continue
            target = self.streams[stream]
            offset = len(target)
            target.extend(chunk)
            if len(target) > MAX_STREAM_BYTES:
                raise ProducerError("target_output_limit_exceeded")
            self._record("receive", stream, chunk, offset)

    def _wait_stdout(
        self,
        start: int,
        maximum: int,
        finder: Any,
    ) -> tuple[int, int, object]:
        while True:
            stdout = bytes(self.streams["stdout"])
            found = finder(stdout)
            if found is not None:
                begin, end, value = found
                if end - start > maximum:
                    raise ProducerError("step_read_limit_exceeded")
                return begin, end, value
            if len(stdout) - start > maximum:
                raise ProducerError("step_read_limit_exceeded")
            if (
                "stdout" not in self.open_streams
                or self.process.poll() is not None
            ):
                self._read_ready(0)
                stdout = bytes(self.streams["stdout"])
                found = finder(stdout)
                if found is not None:
                    begin, end, value = found
                    if end - start <= maximum:
                        return begin, end, value
                raise ProducerError("expected_output_missing")
            self._read_ready(min(0.05, self._remaining()))

    def _dag_node(
        self,
        *,
        step_id: str,
        name: str,
        op: str,
        value_type: str,
        value: int | bytes,
        dependencies: frozenset[str],
        substituted: bool,
    ) -> None:
        encoded = (
            struct.pack("<Q", value)
            if value_type == "u64" and type(value) is int
            else bytes(value)
        )
        node: dict[str, object] = {
            "control_substituted": substituted,
            "dependencies": sorted(dependencies),
            "name": name,
            "op": op,
            "sha256": _sha256(encoded),
            "size_bytes": len(encoded),
            "step_id": step_id,
            "type": value_type,
        }
        if value_type == "u64":
            node["u64"] = value
        self.dag.append(node)

    def _define(
        self,
        *,
        step_id: str,
        name: str,
        op: str,
        value_type: str,
        value: int | bytes,
        references: Sequence[str] = (),
    ) -> None:
        dependencies = {name}
        for reference in references:
            dependencies.update(self.values[reference][2])
        substituted = False
        if name == self.effect_ref:
            if value_type != "u64":
                raise ProducerError("effect_address_type_invalid")
            if self.phase == "control":
                value = 0
                substituted = True
                self.effect_substituted = True
            elif value == 0:
                raise ProducerError("effect_address_zero")
        self.values[name] = (
            value_type,
            value,
            frozenset(dependencies),
        )
        self._dag_node(
            step_id=step_id,
            name=name,
            op=op,
            value_type=value_type,
            value=value,
            dependencies=frozenset(dependencies),
            substituted=substituted,
        )

    def _u64(self, operand: object) -> tuple[int, str | None]:
        if type(operand) is not dict:
            raise ProducerError("runtime_operand_invalid")
        if frozenset(operand) == {"value"}:
            return int(operand["value"]), None
        reference = str(operand["ref"])
        kind, value, _dependencies = self.values[reference]
        if kind != "u64" or type(value) is not int:
            raise ProducerError("runtime_operand_invalid")
        return value, reference

    def _bytes_part(self, part: object) -> tuple[bytes, str | None]:
        if type(part) is not dict:
            raise ProducerError("runtime_operand_invalid")
        if frozenset(part) == {"literal"}:
            return _literal_bytes(part["literal"]), None
        reference = str(part["ref"])
        kind, value, _dependencies = self.values[reference]
        if kind != "bytes" or type(value) is not bytes:
            raise ProducerError("runtime_operand_invalid")
        return value, reference

    def _send(self, payload: bytes) -> None:
        if not payload or len(payload) > MAX_SEND_BYTES:
            raise ProducerError("runtime_send_limit_exceeded")
        if self.stdin.closed:
            raise ProducerError("stdin_already_closed")
        self.total_sent += len(payload)
        if self.total_sent > MAX_AGGREGATE_SEND_BYTES:
            raise ProducerError("runtime_send_limit_exceeded")
        offset = 0
        while offset < len(payload):
            self._read_ready(0)
            try:
                _readable, writable, _errors = select.select(
                    [],
                    [self.stdin_fd],
                    [],
                    min(0.05, self._remaining()),
                )
            except (OSError, ValueError) as error:
                raise ProducerError("target_pipe_write_failed") from error
            if not writable:
                if self.process.poll() is not None:
                    raise ProducerError("target_exited_before_send")
                continue
            try:
                count = os.write(self.stdin_fd, payload[offset:])
            except (BrokenPipeError, OSError) as error:
                raise ProducerError("target_pipe_write_failed") from error
            if count <= 0:
                raise ProducerError("target_pipe_write_failed")
            offset += count
        self._record("send", "stdin", payload, self.total_sent - len(payload))

    def _expect_exact(self, item: Mapping[str, object]) -> None:
        expected = _literal_bytes(item["data"])
        start = self.stdout_cursor

        def finder(stdout: bytes) -> tuple[int, int, object] | None:
            index = stdout.find(expected, start)
            if index < 0:
                return None
            return index, index + len(expected), None

        _begin, end, _value = self._wait_stdout(
            start,
            int(item["max_read_bytes"]),
            finder,
        )
        self.stdout_cursor = end

    def _expect_regex(self, item: Mapping[str, object]) -> None:
        pattern = re.compile(_safe_regex(item["pattern"]))
        start = self.stdout_cursor

        def finder(stdout: bytes) -> tuple[int, int, object] | None:
            newline = stdout.find(b"\n", start)
            if newline < 0:
                return None
            line = stdout[start:newline]
            if pattern.fullmatch(line) is None:
                raise ProducerError("expected_regex_mismatch")
            return start, newline + 1, None

        _begin, end, _value = self._wait_stdout(
            start,
            int(item["max_read_bytes"]),
            finder,
        )
        self.stdout_cursor = end

    def _capture_hex(self, item: Mapping[str, object]) -> int:
        prefix = _literal_bytes(item["prefix"])
        start = self.stdout_cursor

        def finder(stdout: bytes) -> tuple[int, int, object] | None:
            index = stdout.find(prefix, start)
            if index < 0:
                return None
            value_start = index + len(prefix)
            cursor = value_start
            while (
                cursor < len(stdout)
                and cursor - value_start < 16
                and stdout[cursor] in b"0123456789abcdefABCDEF"
            ):
                cursor += 1
            if cursor == value_start:
                return None
            if cursor == len(stdout) and self.process.poll() is None:
                return None
            if (
                cursor - value_start == 16
                and cursor < len(stdout)
                and stdout[cursor] in b"0123456789abcdefABCDEF"
            ):
                raise ProducerError("capture_hex_overflow")
            try:
                value = int(stdout[value_start:cursor], 16)
            except ValueError as error:
                raise ProducerError("capture_hex_invalid") from error
            return index, cursor, value

        _begin, end, value = self._wait_stdout(
            start,
            int(item["max_read_bytes"]),
            finder,
        )
        self.stdout_cursor = end
        return int(value)

    def _capture_u64_line(self, item: Mapping[str, object]) -> int:
        start = self.stdout_cursor

        def finder(stdout: bytes) -> tuple[int, int, object] | None:
            newline = stdout.find(b"\n", start)
            if newline < 0:
                return None
            raw = stdout[start:newline]
            if not 1 <= len(raw) <= 8:
                raise ProducerError("capture_u64_line_invalid")
            return start, newline + 1, int.from_bytes(
                raw.ljust(8, b"\0"),
                "little",
            )

        _begin, end, value = self._wait_stdout(
            start,
            int(item["max_read_bytes"]),
            finder,
        )
        self.stdout_cursor = end
        return int(value)

    def execute(self) -> None:
        steps = self.recipe["steps"]
        if type(steps) is not list:
            raise ProducerError("runtime_recipe_invalid")
        for item in steps:
            if type(item) is not dict:
                raise ProducerError("runtime_recipe_invalid")
            step_id = str(item["id"])
            op = str(item["op"])
            if op == "expect_exact":
                self._expect_exact(item)
            elif op == "expect_safe_regex":
                self._expect_regex(item)
            elif op == "capture_hex":
                value = self._capture_hex(item)
                self._define(
                    step_id=step_id,
                    name=str(item["name"]),
                    op=op,
                    value_type="u64",
                    value=value,
                )
            elif op == "capture_u64_line":
                value = self._capture_u64_line(item)
                self._define(
                    step_id=step_id,
                    name=str(item["name"]),
                    op=op,
                    value_type="u64",
                    value=value,
                )
            elif op == "set_u64":
                self._define(
                    step_id=step_id,
                    name=str(item["name"]),
                    op=op,
                    value_type="u64",
                    value=int(item["value"]),
                )
            elif op == "derive_u64":
                left, left_ref = self._u64(item["left"])
                right, right_ref = self._u64(item["right"])
                operator = item["operator"]
                if operator == "add":
                    value = left + right
                    if value > _U64_MAX:
                        raise ProducerError("checked_add_overflow")
                elif operator == "sub":
                    if left < right:
                        raise ProducerError("checked_sub_underflow")
                    value = left - right
                elif operator == "and":
                    value = left & right
                elif operator == "or":
                    value = left | right
                elif operator == "xor":
                    value = left ^ right
                else:
                    raise ProducerError("runtime_operator_invalid")
                self._define(
                    step_id=step_id,
                    name=str(item["name"]),
                    op=op,
                    value_type="u64",
                    value=value,
                    references=tuple(
                        ref
                        for ref in (left_ref, right_ref)
                        if ref is not None
                    ),
                )
            elif op == "assert_u64":
                left, _left_ref = self._u64(item["left"])
                right, _right_ref = self._u64(item["right"])
                comparison = item["comparison"]
                passed = {
                    "eq": left == right,
                    "ne": left != right,
                    "lt": left < right,
                    "le": left <= right,
                    "gt": left > right,
                    "ge": left >= right,
                    "aligned": right != 0 and left % right == 0,
                }[str(comparison)]
                if not passed:
                    raise ProducerError("runtime_assertion_failed")
            elif op == "literal":
                self._define(
                    step_id=step_id,
                    name=str(item["name"]),
                    op=op,
                    value_type="bytes",
                    value=_literal_bytes(item["data"]),
                )
            elif op == "pack_u64":
                value, reference = self._u64(item["value"])
                self._define(
                    step_id=step_id,
                    name=str(item["name"]),
                    op=op,
                    value_type="bytes",
                    value=struct.pack("<Q", value),
                    references=(
                        () if reference is None else (reference,)
                    ),
                )
            elif op == "concat":
                chunks: list[bytes] = []
                references: list[str] = []
                for part in item["parts"]:
                    chunk, reference = self._bytes_part(part)
                    chunks.append(chunk)
                    if reference is not None:
                        references.append(reference)
                value = b"".join(chunks)
                if len(value) > MAX_SEND_BYTES:
                    raise ProducerError("runtime_value_limit_exceeded")
                self._define(
                    step_id=step_id,
                    name=str(item["name"]),
                    op=op,
                    value_type="bytes",
                    value=value,
                    references=references,
                )
            elif op == "send":
                chunks = [
                    self._bytes_part(part)[0] for part in item["parts"]
                ]
                payload = b"".join(chunks)
                if item["mode"] == "line":
                    payload += b"\n"
                self._send(payload)
            elif op == "delay":
                finish = time.monotonic() + int(item["milliseconds"]) / 1000
                while time.monotonic() < finish:
                    self._read_ready(
                        min(0.05, finish - time.monotonic())
                    )
            elif op == "shutdown_stdin":
                if not self.stdin.closed:
                    self.stdin.close()
            else:
                raise ProducerError("runtime_operation_invalid")
        if self.phase == "control" and not self.effect_substituted:
            raise ProducerError("control_substitution_missing")

    def finish(self) -> bool:
        if not self.stdin.closed:
            self.stdin.close()
        timed_out = False
        while True:
            self._read_ready(0)
            if self.process.poll() is not None:
                drain_deadline = min(
                    self.deadline,
                    time.monotonic() + 2,
                )
                while self.open_streams:
                    if time.monotonic() >= drain_deadline:
                        raise ProducerError(
                            "target_output_drain_incomplete"
                        )
                    self._read_ready(
                        min(
                            0.05,
                            drain_deadline - time.monotonic(),
                        )
                    )
                break
            if time.monotonic() >= self.deadline:
                timed_out = True
                break
            self._read_ready(min(0.05, self._remaining()))
        return timed_out


def _binding(args: argparse.Namespace) -> dict[str, object]:
    return {
        "configuration_epoch": args.configuration_epoch,
        "image_digest": args.image_digest,
        "network": "none",
        "ordinal": args.ordinal,
        "phase": args.phase,
        "preissue_sha256": args.preissue_sha256,
        "producer_sha256": _self_sha256(),
        "recipe_sha256": args.recipe_sha256,
        "recipe_size_bytes": args.recipe_size_bytes,
        "source_manifest_sha256": args.source_manifest_sha256,
        "source_sha256": args.source_sha256,
        "source_size_bytes": args.source_size_bytes,
    }


def _failure_document(
    args: argparse.Namespace,
    reason_code: str,
) -> bytes:
    return _canonical_json_bytes(
        {
            "binding": _binding(args),
            "contract": {
                "id": PRODUCER_CONTRACT_ID,
                "protocol": PRODUCER_PROTOCOL,
                "recipe_contract_fingerprint": CONTRACT_FINGERPRINT,
                "version": PRODUCER_CONTRACT_VERSION,
            },
            "observation": None,
            "reason_code": reason_code,
            "schema_version": SCHEMA_VERSION,
            "status": "unverifiable",
        }
    )


def _run(args: argparse.Namespace) -> bytes:
    if args.ordinal > 3:
        raise ProducerError("ordinal_out_of_range")
    _protect_producer()
    if _descendant_pids(os.getpid()):
        raise ProducerError("producer_preexisting_descendant")
    source_descriptor, _source = _read_regular_exact(
        args.binary,
        root=CHALLENGE_ROOT,
        expected_sha256=args.source_sha256,
        expected_size=args.source_size_bytes,
        maximum_bytes=MAX_SOURCE_BYTES,
        executable=True,
        retain=False,
    )
    recipe_descriptor = -1
    process: subprocess.Popen[bytes] | None = None
    sentinel_path = WORK_ROOT / SENTINEL_PATH_RELATIVE
    sentinel_created = False
    runtime: _Runtime | None = None
    try:
        recipe_descriptor, recipe_bytes = _read_regular_exact(
            args.recipe,
            root=WORK_ROOT,
            expected_sha256=args.recipe_sha256,
            expected_size=args.recipe_size_bytes,
            maximum_bytes=MAX_RECIPE_BYTES,
            executable=False,
            retain=True,
        )
        recipe = _parse_recipe(recipe_bytes)
        output_directory = _ensure_output_directory(
            args.recipe_sha256,
            args.phase,
            args.ordinal,
        )

        sentinel = (
            SENTINEL_PREFIX
            + secrets.token_hex(32).encode("ascii")
            + b"\n"
        )
        if SENTINEL_RE.fullmatch(sentinel) is None:
            raise ProducerError("sentinel_generation_failed")
        _write_immutable(sentinel_path, sentinel, 256)
        sentinel_created = True

        started = time.monotonic()
        try:
            process = subprocess.Popen(
                [f"/proc/self/fd/{source_descriptor}"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=WORK_ROOT,
                env=FIXED_ENVIRONMENT,
                close_fds=True,
                pass_fds=(source_descriptor,),
                start_new_session=True,
                preexec_fn=_child_limits,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise ProducerError("target_exec_failed") from error
        runtime = _Runtime(
            process,
            recipe,
            phase=args.phase,
            started=started,
        )
        runtime.execute()
        timed_out = runtime.finish()
        returncode_before_cleanup = process.poll()
        process_group_cleaned = _terminate_process_tree(process)
        elapsed_milliseconds = int(
            (time.monotonic() - started) * 1000
        )
        target_stdout = bytes(runtime.streams["stdout"])
        target_stderr = bytes(runtime.streams["stderr"])
        combined = target_stdout + target_stderr
        sentinel_occurrences = combined.count(sentinel)
        shaped_occurrences = len(SENTINEL_RE.findall(combined))

        transcript = _canonical_json_bytes(
            {
                "binding": {
                    "ordinal": args.ordinal,
                    "phase": args.phase,
                    "recipe_sha256": args.recipe_sha256,
                },
                "events": runtime.transcript,
                "schema_version": 1,
            }
        )
        dag = _canonical_json_bytes(
            {
                "binding": {
                    "ordinal": args.ordinal,
                    "phase": args.phase,
                    "recipe_sha256": args.recipe_sha256,
                },
                "nodes": runtime.dag,
                "schema_version": 1,
            }
        )
        stdout_path = output_directory / "target.stdout.bin"
        stderr_path = output_directory / "target.stderr.bin"
        transcript_path = output_directory / "transcript.json"
        dag_path = output_directory / "derivation-dag.json"
        _write_immutable(
            stdout_path,
            target_stdout,
            MAX_STREAM_BYTES,
        )
        _write_immutable(
            stderr_path,
            target_stderr,
            MAX_STREAM_BYTES,
        )
        _write_immutable(
            transcript_path,
            transcript,
            MAX_TRANSCRIPT_BYTES,
        )
        _write_immutable(dag_path, dag, MAX_DAG_BYTES)

        if timed_out:
            status = "unverifiable"
            reason_code = "target_timeout"
        elif not process_group_cleaned:
            status = "unverifiable"
            reason_code = "process_group_cleanup_failed"
        elif sentinel_occurrences == 1 and shaped_occurrences == 1:
            status = "effect_observed"
            reason_code = "unpredictable_sentinel_emitted"
        elif sentinel_occurrences == 0 and shaped_occurrences == 0:
            status = "effect_absent"
            reason_code = "sentinel_not_emitted"
        else:
            status = "unverifiable"
            reason_code = "sentinel_output_ambiguous"

        final_returncode = (
            returncode_before_cleanup
            if returncode_before_cleanup is not None
            else process.returncode
        )
        observation = {
            "control_substitution_applied": (
                runtime.effect_substituted
            ),
            "derivation_dag_path": (
                dag_path.relative_to(WORK_ROOT).as_posix()
            ),
            "derivation_dag_sha256": _sha256(dag),
            "derivation_dag_size_bytes": len(dag),
            "elapsed_milliseconds": elapsed_milliseconds,
            "process_group_cleaned": process_group_cleaned,
            "sentinel_occurrences": sentinel_occurrences,
            "sentinel_sha256": _sha256(sentinel),
            "stderr_path": stderr_path.relative_to(WORK_ROOT).as_posix(),
            "stderr_sha256": _sha256(target_stderr),
            "stderr_size_bytes": len(target_stderr),
            "stdout_path": stdout_path.relative_to(WORK_ROOT).as_posix(),
            "stdout_sha256": _sha256(target_stdout),
            "stdout_size_bytes": len(target_stdout),
            "target_exit_code": (
                final_returncode
                if final_returncode is not None
                and final_returncode >= 0
                else None
            ),
            "target_signal": (
                -final_returncode
                if final_returncode is not None
                and final_returncode < 0
                else None
            ),
            "timed_out": timed_out,
            "transcript_path": (
                transcript_path.relative_to(WORK_ROOT).as_posix()
            ),
            "transcript_sha256": _sha256(transcript),
            "transcript_size_bytes": len(transcript),
        }
        document = {
            "binding": _binding(args),
            "contract": {
                "id": PRODUCER_CONTRACT_ID,
                "protocol": PRODUCER_PROTOCOL,
                "recipe_contract_fingerprint": CONTRACT_FINGERPRINT,
                "version": PRODUCER_CONTRACT_VERSION,
            },
            "observation": observation,
            "reason_code": reason_code,
            "schema_version": SCHEMA_VERSION,
            "status": status,
        }
        encoded = _canonical_json_bytes(document)
        if len(encoded) > MAX_DOCUMENT_BYTES:
            raise ProducerError("document_size_limit_exceeded")
        return encoded
    finally:
        if process is not None and process.poll() is None:
            _terminate_process_tree(process)
        if process is not None:
            for pipe in (
                process.stdin,
                process.stdout,
                process.stderr,
            ):
                if pipe is not None and not pipe.closed:
                    try:
                        pipe.close()
                    except OSError:
                        pass
        for descriptor in (recipe_descriptor, source_descriptor):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if sentinel_created:
            try:
                sentinel_path.unlink()
            except FileNotFoundError:
                pass
            except OSError as error:
                raise ProducerError("sentinel_cleanup_failed") from error


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        document = _run(args)
    except ProducerError as error:
        document = _failure_document(args, error.reason_code)
    try:
        sys.stdout.buffer.write(document)
        sys.stdout.buffer.flush()
    except BrokenPipeError:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
