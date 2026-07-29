#!/usr/bin/env python3
"""Produce one bounded, source-bound Rev inventory observation.

The engine runs this template inside the challenge-scoped, network-denied
sandbox.  It reads one immutable regular file from /challenge, invokes only
the local rabin2 binary, normalizes the small ``-Ij`` response, and atomically
publishes canonical JSON beneath /work/rev.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from safe_output import atomic_write, open_output_dir, remove_regular_output


SCHEMA_VERSION = 1
CONTRACT_ID = "ctfos.rev.inventory"
CONTRACT_VERSION = 1
OUTPUT_NAME = "inventory-v1.json"
OUTPUT_DIR = Path("/work/rev")
RABIN2_EXECUTABLE = "/usr/bin/rabin2"

MAX_SOURCE_BYTES = 1024 * 1024 * 1024
SOURCE_HASH_TIMEOUT_SECONDS = 30
RABIN2_TIMEOUT_SECONDS = 30
MAX_RABIN2_STDOUT_BYTES = 64 * 1024
MAX_RABIN2_STDERR_BYTES = 16 * 1024
MAX_INVENTORY_BYTES = 16 * 1024
MAX_JSON_DEPTH = 8

_CONTRACT_DESCRIPTOR = {
    "contract_id": CONTRACT_ID,
    "contract_version": CONTRACT_VERSION,
    "document_shape": (
        "contract(fingerprint,id,version);schema_version;status;"
        "source(sha256,size_bytes);"
        "ok:binary(arch,bits,bintype,endian,havecode)|error:error(code)"
    ),
    "inventory_max_bytes": MAX_INVENTORY_BYTES,
    "json": "utf8-canonical-strict-v1",
    "output_name": OUTPUT_NAME,
    "rabin2_executable": RABIN2_EXECUTABLE,
    "rabin2_mode": "-Ij",
    "rabin2_stderr_max_bytes": MAX_RABIN2_STDERR_BYTES,
    "rabin2_stdout_max_bytes": MAX_RABIN2_STDOUT_BYTES,
    "rabin2_timeout_seconds": RABIN2_TIMEOUT_SECONDS,
    "source_hash": "sha256",
    "source_hash_timeout_seconds": SOURCE_HASH_TIMEOUT_SECONDS,
    "source_max_bytes": MAX_SOURCE_BYTES,
    "stale_output": "remove-regular-before-source-open",
}


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


CONTRACT_FINGERPRINT = hashlib.sha256(
    _canonical_json_bytes(_CONTRACT_DESCRIPTOR)
).hexdigest()

_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_.+-]{1,64}$")
_BINTYPE_ALIASES = {
    "dex": "dex",
    "elf": "elf",
    "java": "java",
    "mach-o": "mach_o",
    "mach0": "mach_o",
    "mach_o": "mach_o",
    "pe": "pe",
    "wasm": "wasm",
}
_ERROR_CODES = frozenset(
    {
        "rabin2_failed",
        "rabin2_invalid_json",
        "rabin2_invalid_schema",
        "rabin2_stderr_limit",
        "rabin2_stdout_limit",
        "rabin2_timeout",
    }
)


class InventoryError(RuntimeError):
    """Expected producer failure with a stable, non-sensitive reason code."""

    def __init__(self, code: str) -> None:
        if code not in _ERROR_CODES:
            raise ValueError(f"unsupported inventory error code: {code}")
        super().__init__(code)
        self.code = code


class DuplicateKeyError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class SourceBinding:
    sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _json_depth(value: object) -> int:
    if isinstance(value, dict):
        return 1 + max((_json_depth(item) for item in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((_json_depth(item) for item in value), default=0)
    return 1


def _strict_json_loads(payload: bytes, *, maximum_bytes: int) -> object:
    if len(payload) > maximum_bytes:
        raise ValueError("JSON output exceeds its byte limit")
    text = payload.decode("utf-8", errors="strict")
    value = json.loads(
        text,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_json_constant,
    )
    if _json_depth(value) > MAX_JSON_DEPTH:
        raise ValueError("JSON output exceeds its depth limit")
    return value


def _stable_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _open_and_hash_source(path: Path) -> tuple[int, SourceBinding, tuple[int, ...]]:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise OSError("source is not a regular file")
        if before.st_size > MAX_SOURCE_BYTES:
            raise OSError("source exceeds the Rev inventory byte limit")

        deadline = time.monotonic() + SOURCE_HASH_TIMEOUT_SECONDS
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            if time.monotonic() >= deadline:
                raise TimeoutError("source hash deadline exceeded")
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise OSError("source was truncated while hashing")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise OSError("source grew while hashing")
        after = os.fstat(descriptor)
        identity = _stable_identity(before)
        if _stable_identity(after) != identity:
            raise OSError("source changed while hashing")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return (
            descriptor,
            SourceBinding(
                sha256=digest.hexdigest(),
                size_bytes=before.st_size,
            ),
            identity,
        )
    except BaseException:
        os.close(descriptor)
        raise


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    # The direct child may already have exited while a descendant still holds
    # a captured pipe open.  Kill by the dedicated process-group id even in
    # that case; limiting cleanup to ``process.poll() is None`` would leak it.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _run_bounded(
    argv: tuple[str, ...],
    *,
    pass_fds: tuple[int, ...] = (),
    timeout_seconds: float = RABIN2_TIMEOUT_SECONDS,
    stdout_limit_bytes: int = MAX_RABIN2_STDOUT_BYTES,
    stderr_limit_bytes: int = MAX_RABIN2_STDERR_BYTES,
) -> CommandResult:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    if stdout_limit_bytes <= 0 or stderr_limit_bytes <= 0:
        raise ValueError("stream limits must be positive")

    environment = {
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "RABIN2_DEMANGLE": "0",
        "RABIN2_NOPLUGINS": "1",
        "RABIN2_PDBSERVER": "",
        "RABIN2_SWIFTLIB": "0",
        "RABIN2_SYMSTORE": "",
        "TERM": "dumb",
    }
    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        env=environment,
        pass_fds=pass_fds,
        start_new_session=True,
    )
    if process.stdout is None or process.stderr is None:
        _kill_process_group(process)
        raise RuntimeError("could not capture rabin2 output")

    streams = {
        process.stdout.fileno(): ("stdout", process.stdout, stdout_limit_bytes),
        process.stderr.fileno(): ("stderr", process.stderr, stderr_limit_bytes),
    }
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    for descriptor in streams:
        selector.register(descriptor, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout_seconds
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _kill_process_group(process)
                raise InventoryError("rabin2_timeout")
            events = selector.select(timeout=min(remaining, 0.25))
            if not events:
                continue
            for key, _mask in events:
                descriptor = int(key.fd)
                stream_name, stream, limit = streams[descriptor]
                remaining_capacity = limit + 1 - len(captured[stream_name])
                chunk = os.read(
                    descriptor,
                    min(64 * 1024, max(1, remaining_capacity)),
                )
                if not chunk:
                    selector.unregister(descriptor)
                    stream.close()
                    continue
                captured[stream_name].extend(chunk)
                if len(captured[stream_name]) > limit:
                    _kill_process_group(process)
                    raise InventoryError(f"rabin2_{stream_name}_limit")

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _kill_process_group(process)
            raise InventoryError("rabin2_timeout")
        returncode = process.wait(timeout=remaining)
    except subprocess.TimeoutExpired as exc:
        _kill_process_group(process)
        raise InventoryError("rabin2_timeout") from exc
    except BaseException:
        _kill_process_group(process)
        raise
    finally:
        selector.close()
        for _name, stream, _limit in streams.values():
            if not stream.closed:
                stream.close()

    return CommandResult(
        returncode=returncode,
        stdout=bytes(captured["stdout"]),
        stderr=bytes(captured["stderr"]),
    )


def _require_exact_type(value: object, expected: type, label: str) -> None:
    if type(value) is not expected:
        raise ValueError(f"{label} has the wrong type")


def _normalize_token(
    value: object,
    *,
    label: str,
    empty: str | None,
) -> str | None:
    _require_exact_type(value, str, label)
    normalized = value.strip().lower()
    if not normalized:
        return empty
    if not _SAFE_TOKEN.fullmatch(normalized):
        raise ValueError(f"{label} is not a safe token")
    return normalized


def _normalize_rabin2_info(payload: bytes, source_size: int) -> dict[str, object]:
    try:
        root = _strict_json_loads(
            payload,
            maximum_bytes=MAX_RABIN2_STDOUT_BYTES,
        )
        if not isinstance(root, dict) or set(root) != {"info"}:
            raise ValueError("rabin2 root must contain only info")
        info = root["info"]
        if not isinstance(info, dict):
            raise ValueError("rabin2 info must be an object")
        required = {
            "arch",
            "binsz",
            "bintype",
            "bits",
            "endian",
            "havecode",
        }
        if not required <= set(info):
            raise ValueError("rabin2 info is missing required fields")

        _require_exact_type(info["binsz"], int, "binsz")
        if not 0 <= info["binsz"] <= source_size:
            raise ValueError("rabin2 size is outside the source")
        _require_exact_type(info["bits"], int, "bits")
        bits = info["bits"]
        if bits == 0:
            normalized_bits: int | None = None
        elif bits in {8, 16, 32, 64}:
            normalized_bits = bits
        else:
            raise ValueError("rabin2 bits are unsupported")
        _require_exact_type(info["havecode"], bool, "havecode")

        arch = _normalize_token(info["arch"], label="arch", empty=None)
        raw_bintype = _normalize_token(
            info["bintype"],
            label="bintype",
            empty="unknown",
        )
        bintype = _BINTYPE_ALIASES.get(raw_bintype, "unknown")
        raw_endian = _normalize_token(
            info["endian"],
            label="endian",
            empty="unknown",
        )
        endian = (
            raw_endian
            if raw_endian in {"big", "little", "mixed", "unknown"}
            else "unknown"
        )
        return {
            "arch": arch,
            "bits": normalized_bits,
            "bintype": bintype,
            "endian": endian,
            "havecode": info["havecode"],
        }
    except (
        DuplicateKeyError,
        json.JSONDecodeError,
        RecursionError,
        UnicodeDecodeError,
        ValueError,
    ) as exc:
        if isinstance(
            exc,
            (
                DuplicateKeyError,
                json.JSONDecodeError,
                RecursionError,
                UnicodeDecodeError,
            ),
        ):
            raise InventoryError("rabin2_invalid_json") from exc
        raise InventoryError("rabin2_invalid_schema") from exc


def _base_document(source: SourceBinding) -> dict[str, object]:
    return {
        "contract": {
            "fingerprint": CONTRACT_FINGERPRINT,
            "id": CONTRACT_ID,
            "version": CONTRACT_VERSION,
        },
        "schema_version": SCHEMA_VERSION,
        "source": {
            "sha256": source.sha256,
            "size_bytes": source.size_bytes,
        },
    }


def _success_document(
    source: SourceBinding,
    binary: dict[str, object],
) -> dict[str, object]:
    return {
        **_base_document(source),
        "binary": binary,
        "status": "ok",
    }


def _error_document(source: SourceBinding, code: str) -> dict[str, object]:
    if code not in _ERROR_CODES:
        raise ValueError("unsupported producer error")
    return {
        **_base_document(source),
        "error": {"code": code},
        "status": "error",
    }


def _publish_document(output_descriptor: int, document: dict[str, object]) -> None:
    encoded = _canonical_json_bytes(document)
    if len(encoded) > MAX_INVENTORY_BYTES:
        raise OSError("normalized inventory exceeds its byte limit")
    atomic_write(output_descriptor, OUTPUT_NAME, encoded)


def produce_inventory(
    source_path: Path,
    output_dir: Path = OUTPUT_DIR,
    *,
    rabin2_executable: str = RABIN2_EXECUTABLE,
) -> bool:
    """Publish one inventory; return whether rabin2 produced usable metadata."""

    output_descriptor = open_output_dir(output_dir)
    source_descriptor: int | None = None
    try:
        # A fatal source/hash error cannot leave a prior successful observation
        # available for a later run to snapshot as if it were fresh.
        remove_regular_output(output_descriptor, OUTPUT_NAME)
        source_descriptor, source, identity = _open_and_hash_source(source_path)
        try:
            result = _run_bounded(
                (
                    rabin2_executable,
                    "-Ij",
                    f"/proc/self/fd/{source_descriptor}",
                ),
                pass_fds=(source_descriptor,),
            )
            if result.returncode != 0:
                raise InventoryError("rabin2_failed")
            binary = _normalize_rabin2_info(
                result.stdout,
                source.size_bytes,
            )
            if _stable_identity(os.fstat(source_descriptor)) != identity:
                raise OSError("source changed during rabin2 inspection")
        except InventoryError as error:
            _publish_document(
                output_descriptor,
                _error_document(source, error.code),
            )
            return False
        _publish_document(
            output_descriptor,
            _success_document(source, binary),
        )
        return True
    finally:
        if source_descriptor is not None:
            os.close(source_descriptor)
        os.close(output_descriptor)


def _challenge_source(argument: str) -> Path:
    source = Path(argument)
    if not source.is_absolute():
        raise ValueError("source path must be absolute")
    challenge_root = Path("/challenge").resolve(strict=True)
    parent = source.parent.resolve(strict=True)
    if parent != challenge_root and challenge_root not in parent.parents:
        raise ValueError("source path must stay beneath /challenge")
    return parent / source.name


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("Usage: inventory.py /challenge/BINARY", file=sys.stderr)
        return 2
    try:
        source = _challenge_source(argv[0])
        observed = produce_inventory(source)
    except (OSError, TimeoutError, ValueError) as error:
        print(f"rev inventory: {type(error).__name__}: {error}", file=sys.stderr)
        return 1
    return 0 if observed else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
