#!/usr/bin/env python3
"""Real-Docker Python fixture for exact file-range observations.

The ``descriptor`` implementation hashes through a no-follow file descriptor
and reads the selected range with ``pread``.  The ``mmap`` implementation
resolves the source, hashes an immutable mapping, and slices the same range.
These are two modes of one Python producer, so both deliberately report the
same executable-version identity.  Cross-tool corroboration is supplied by a
separate Perl producer.  Both modes emit a raw-bearing private artifact and a
canonical, value-free observation document bound to the engine-issued request.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import os
import stat
from pathlib import Path


PROTOCOL = "ctfos.release.forensic.assertion.tool.v1"
EXECUTION_PROTOCOL = "ctfos.forensic.assertion.execution.v1"
SCHEMA_VERSION = 1
ALGORITHMS = ("descriptor", "mmap")
MAX_REQUEST_BYTES = 256 * 1024
MAX_SOURCE_BYTES = 16 * 1024 * 1024


class FixtureError(ValueError):
    """The release fixture rejected a request or source binding."""


def canonical_json(value: object) -> bytes:
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


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def tool_version_sha256(
    source: bytes,
    *,
    algorithm: str,
    corrupt_binding: bool,
) -> str:
    if algorithm not in ALGORITHMS or type(corrupt_binding) is not bool:
        raise FixtureError("tool_version_input_invalid")
    if type(source) is not bytes or not source:
        raise FixtureError("tool_version_input_invalid")
    # The semantic mode and negative-control flag are request contracts, not
    # independent implementations.  Version identity is the actual pinned
    # image executable, so two labels around this file cannot masquerade as
    # cross-tool corroboration.
    return sha256(Path("/usr/bin/python3").read_bytes())


def _safe_relative(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or value.startswith("/")
        or "\\" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise FixtureError("relative_path_invalid")
    return value


def _output_path(value: object) -> Path:
    relative = _safe_relative(value)
    destination = Path.cwd().joinpath(*relative.split("/"))
    destination.parent.mkdir(parents=True, exist_ok=True)
    return destination


def _source_path(value: object) -> Path:
    relative = _safe_relative(value)
    root = Path("/challenge").resolve(strict=True)
    cursor = root
    for component in relative.split("/"):
        cursor = cursor / component
        if cursor.is_symlink():
            raise FixtureError("source_symlink_rejected")
    resolved = cursor.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise FixtureError("source_escape_rejected") from error
    if not resolved.is_file():
        raise FixtureError("source_not_regular")
    return resolved


def _bounded_request(path: str) -> tuple[bytes, dict[str, object]]:
    source = Path.cwd().joinpath(*_safe_relative(path).split("/"))
    before = source.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_REQUEST_BYTES:
        raise FixtureError("request_not_bounded_regular")
    payload = source.read_bytes()
    after = source.stat()
    if (
        len(payload) != before.st_size
        or (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
    ):
        raise FixtureError("request_changed")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FixtureError("request_json_invalid") from error
    if type(value) is not dict or payload != canonical_json(value):
        raise FixtureError("request_not_canonical")
    return payload, value


def _pointer(
    request: dict[str, object],
) -> tuple[Path, dict[str, object], int, int]:
    raw = request.get("pointer")
    if (
        type(raw) is not dict
        or raw.get("kind") != "file_range"
        or type(raw.get("source_sha256")) is not str
        or type(raw.get("offset_bytes")) is not int
        or type(raw.get("length_bytes")) is not int
        or raw["offset_bytes"] < 0
        or raw["length_bytes"] < 1
    ):
        raise FixtureError("pointer_invalid")
    source = _source_path(raw.get("source_path"))
    offset = raw["offset_bytes"]
    length = raw["length_bytes"]
    if source.stat().st_size > MAX_SOURCE_BYTES:
        raise FixtureError("source_too_large")
    if offset + length > source.stat().st_size:
        raise FixtureError("pointer_out_of_bounds")
    return source, raw, offset, length


def _descriptor_read(
    source: Path,
    *,
    offset: int,
    length: int,
    expected_sha256: str,
) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(source, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise FixtureError("descriptor_source_not_regular")
        digest = hashlib.sha256()
        total = 0
        while True:
            block = os.read(descriptor, 64 * 1024)
            if not block:
                break
            digest.update(block)
            total += len(block)
            if total > MAX_SOURCE_BYTES:
                raise FixtureError("descriptor_source_too_large")
        selected = os.pread(descriptor, length, offset)
        after = os.fstat(descriptor)
        if (
            digest.hexdigest() != expected_sha256
            or len(selected) != length
            or (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
        ):
            raise FixtureError("descriptor_source_binding_mismatch")
        return selected
    finally:
        os.close(descriptor)


def _mmap_read(
    source: Path,
    *,
    offset: int,
    length: int,
    expected_sha256: str,
) -> bytes:
    with source.open("rb", buffering=0) as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_SOURCE_BYTES:
            raise FixtureError("mmap_source_not_bounded_regular")
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
            if sha256(mapped[:]) != expected_sha256:
                raise FixtureError("mmap_source_hash_mismatch")
            selected = mapped[offset : offset + length]
        after = os.fstat(stream.fileno())
        if (
            len(selected) != length
            or (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
        ):
            raise FixtureError("mmap_source_binding_mismatch")
        return bytes(selected)


def read_exact_range(
    source: Path,
    *,
    algorithm: str,
    offset: int,
    length: int,
    expected_sha256: str,
) -> bytes:
    if algorithm == "descriptor":
        return _descriptor_read(
            source,
            offset=offset,
            length=length,
            expected_sha256=expected_sha256,
        )
    if algorithm == "mmap":
        return _mmap_read(
            source,
            offset=offset,
            length=length,
            expected_sha256=expected_sha256,
        )
    raise FixtureError("algorithm_invalid")


def _probe(arguments: argparse.Namespace) -> None:
    source = Path(__file__).read_bytes()
    observed_version = tool_version_sha256(
        source,
        algorithm=arguments.algorithm,
        corrupt_binding=arguments.corrupt_binding,
    )
    if observed_version != arguments.expected_tool_version:
        raise FixtureError("probe_tool_version_mismatch")
    document = {
        "algorithm": arguments.algorithm,
        "binding_mode": (
            "pointer_mismatch"
            if arguments.corrupt_binding
            else "exact"
        ),
        "fixture_sha256": sha256(source),
        "image_digest": arguments.expected_image_digest,
        "network": "none",
        "producer_executable": "/usr/bin/python3",
        "producer_executable_sha256": observed_version,
        "protocol": PROTOCOL,
        "schema_version": SCHEMA_VERSION,
        "supported_pointer_kinds": ["file_range"],
        "tool_version_sha256": observed_version,
    }
    _output_path(arguments.probe).write_bytes(canonical_json(document))


def _execute(arguments: argparse.Namespace) -> None:
    request_payload, request = _bounded_request(arguments.request)
    source, pointer, offset, length = _pointer(request)
    source_bytes = source.stat().st_size
    own_source = Path(__file__).read_bytes()
    expected_version = tool_version_sha256(
        own_source,
        algorithm=arguments.algorithm,
        corrupt_binding=arguments.corrupt_binding,
    )
    tool = request.get("tool")
    if (
        type(tool) is not dict
        or tool.get("tool_version_sha256") != expected_version
        or expected_version != arguments.expected_tool_version
        or tool.get("runtime_image_digest")
        != arguments.expected_image_digest
    ):
        raise FixtureError("execution_tool_binding_mismatch")
    selected = read_exact_range(
        source,
        algorithm=arguments.algorithm,
        offset=offset,
        length=length,
        expected_sha256=pointer["source_sha256"],
    )
    private_artifact = canonical_json(
        {
            "algorithm": arguments.algorithm,
            "length_bytes": length,
            "offset_bytes": offset,
            "pointer_id": pointer["pointer_id"],
            "protocol": PROTOCOL,
            "range_hex": selected.hex(),
            "range_sha256": sha256(selected),
            "schema_version": SCHEMA_VERSION,
            "source_path": pointer["source_path"],
            "source_sha256": pointer["source_sha256"],
            "source_size_bytes": source_bytes,
        }
    )
    artifact_path = _output_path(arguments.artifact)
    artifact_path.write_bytes(private_artifact)
    artifact = request["artifact"]
    observation = request["observation"]
    command = request["command"]
    transport_contract = request["transport_contract"]
    source_binding = request["source"]
    pointer_sha256 = (
        "0" * 64
        if arguments.corrupt_binding
        else pointer["sha256"]
    )
    document = {
        "artifact": {
            "artifact_id": artifact["artifact_id"],
            "path": artifact["path"],
            "sha256": sha256(private_artifact),
            "size_bytes": len(private_artifact),
        },
        "capture": {
            "capture_complete": True,
            "capture_error_code": None,
            "truncated": False,
            "truncation_known": True,
        },
        "command_argv_sha256": command["argv_sha256"],
        "command_template_sha256": command["template_sha256"],
        "execution_nonce_sha256": request["execution_nonce_sha256"],
        "index_execution_evaluation_sha256": request[
            "index_execution_evaluation_sha256"
        ],
        "independence_family": tool["independence_family"],
        "observation_id": observation["observation_id"],
        "operator_spec_sha256": request["operator_spec_sha256"],
        "plan_sha256": request["plan_sha256"],
        "pointer_id": pointer["pointer_id"],
        "pointer_kind": pointer["kind"],
        "pointer_sha256": pointer_sha256,
        "protocol": EXECUTION_PROTOCOL,
        "readiness_registry_sha256": request[
            "readiness_registry_sha256"
        ],
        "receipt_id": observation["receipt_id"],
        "request_id": request["request_id"],
        "request_sha256": sha256(request_payload),
        "run_id": request["run_id"],
        "runtime_image_digest": tool["runtime_image_digest"],
        "schema_version": SCHEMA_VERSION,
        "semantic_execution_contract_sha256": request[
            "semantic_execution_contract_sha256"
        ],
        "source_inventory_sha256": source_binding["inventory_sha256"],
        "source_manifest_sha256": source_binding["manifest_sha256"],
        "tool_id": tool["tool_id"],
        "tool_version_sha256": tool["tool_version_sha256"],
        "transport": {
            "clean_workspace": True,
            "evidence_read_only": True,
            "exit_code": 0,
            "network_disabled": True,
            "orchestration_status": "completed",
            "timed_out": False,
        },
        "transport_execution_contract_sha256": transport_contract[
            "transport_execution_contract_sha256"
        ],
    }
    _output_path(arguments.observation).write_bytes(
        canonical_json(document)
    )


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--algorithm", choices=ALGORITHMS, required=True)
    parser.add_argument("--expected-image-digest", required=True)
    parser.add_argument("--expected-tool-version", required=True)
    parser.add_argument("--corrupt-binding", action="store_true")
    parser.add_argument("--probe")
    parser.add_argument("--request")
    parser.add_argument("--observation")
    parser.add_argument("--artifact")
    arguments = parser.parse_args()
    if arguments.probe is not None:
        if any(
            value is not None
            for value in (
                arguments.request,
                arguments.observation,
                arguments.artifact,
            )
        ):
            parser.error("--probe cannot be combined with execution paths")
    elif any(
        value is None
        for value in (
            arguments.request,
            arguments.observation,
            arguments.artifact,
        )
    ):
        parser.error("execution requires request, observation, and artifact")
    return arguments


def main() -> int:
    arguments = _arguments()
    if arguments.probe is not None:
        _probe(arguments)
    else:
        _execute(arguments)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
