#!/usr/bin/env python3
"""Execute one bounded local Crypto/Misc data transcript replay.

Only an engine constructs this command.  The Builder-controlled artifact is a
canonical recipe containing exact ``send`` and ``expect`` byte operations; it
cannot provide a command, argv, interpreter, path, environment, or network
target.  The operator-preissued peer is directly execve'd with exactly one
engine-created fresh-state path argument.

Stdout is reserved for one canonical result document.  Exact peer streams,
the transcript, and a reset proof are private bounded files under /work.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import resource
import secrets
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Mapping, Sequence


SCHEMA_VERSION = 1
RECIPE_CONTRACT_ID = "ctfos.data_transcript.recipe"
RECIPE_CONTRACT_VERSION = 1
RECIPE_PROTOCOL = "crypto_misc_local_data_transcript_v1"
RECIPE_CONTRACT_FINGERPRINT = (
    "d946f794d6af0ab02a20a8d940279607d8cbb511662f5df206fa226aaa66ba67"
)
PRODUCER_CONTRACT_ID = "ctfos.data_transcript.producer"
PRODUCER_CONTRACT_VERSION = 1
PRODUCER_PROTOCOL = "crypto_misc_local_data_transcript_producer_v1"
CONTROL_MUTATION = "first_send_byte_xor_ordinal_bit_v1"
RESET_MODE = "fresh_seed_copy_per_replay_v1"

MAX_RECIPE_BYTES = 64 * 1024
MAX_STEPS = 64
MAX_STEP_BYTES = 64 * 1024
MAX_AGGREGATE_SEND_BYTES = 1024 * 1024
MAX_AGGREGATE_EXPECT_BYTES = 1024 * 1024
MAX_TIMEOUT_MILLISECONDS = 120_000
MAX_PEER_BYTES = 1024 * 1024 * 1024
MAX_PEER_DATA_BYTES = 1024 * 1024 * 1024
MAX_STREAM_BYTES = 1024 * 1024
MAX_TRANSCRIPT_BYTES = 8 * 1024 * 1024
MAX_RESULT_BYTES = 64 * 1024

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SAFE_STEP_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_SAFE_HEX = re.compile(r"^(?:[0-9a-f]{2})*$")
_ROOT_KEYS = frozenset(
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
_FIXED_ENV = {
    "HOME": "/nonexistent",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "PATH": "/usr/bin:/bin",
    "TERM": "dumb",
}


class ProducerError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _fail(code: str) -> None:
    raise ProducerError(code)


def _canonical(value: object) -> bytes:
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
    except (RecursionError, TypeError, UnicodeError, ValueError) as error:
        raise ProducerError("canonical_json_invalid") from error


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate_json_key")
        result[key] = value
    return result


def _mapping(
    value: object,
    keys: frozenset[str],
) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != keys:
        _fail("recipe_schema_invalid")
    return value


def _integer(value: object, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _fail("recipe_schema_invalid")
    return value


def _literal(value: object) -> bytes:
    raw = _mapping(value, _LITERAL_KEYS)
    encoding = raw["encoding"]
    encoded = raw["value"]
    if type(encoded) is not str or encoding not in {"hex", "utf8"}:
        _fail("recipe_literal_invalid")
    try:
        if encoding == "hex":
            if _SAFE_HEX.fullmatch(encoded) is None:
                _fail("recipe_literal_invalid")
            result = bytes.fromhex(encoded)
        else:
            result = encoded.encode("utf-8")
    except (UnicodeError, ValueError) as error:
        raise ProducerError("recipe_literal_invalid") from error
    if not result or len(result) > MAX_STEP_BYTES:
        _fail("recipe_step_byte_limit")
    return result


def _parse_recipe(payload: bytes) -> dict[str, object]:
    if not payload or len(payload) > MAX_RECIPE_BYTES:
        _fail("recipe_size_invalid")
    try:
        payload.decode("ascii")
        value = json.loads(
            payload,
            object_pairs_hook=_duplicate_keys,
            parse_constant=lambda _token: _fail("recipe_json_invalid"),
        )
    except ProducerError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ProducerError("recipe_json_invalid") from error
    if _canonical(value) != payload:
        _fail("recipe_noncanonical")
    root = _mapping(value, _ROOT_KEYS)
    contract = _mapping(root["contract"], _CONTRACT_KEYS)
    if (
        root["schema_version"] != SCHEMA_VERSION
        or contract
        != {
            "id": RECIPE_CONTRACT_ID,
            "protocol": RECIPE_PROTOCOL,
            "version": RECIPE_CONTRACT_VERSION,
        }
    ):
        _fail("recipe_contract_mismatch")
    if root["category"] not in {"crypto", "misc"}:
        _fail("recipe_category_invalid")
    if (
        type(root["preissue_id"]) is not str
        or _SAFE_ID.fullmatch(root["preissue_id"]) is None
        or type(root["reset_commitment_sha256"]) is not str
        or _SHA256.fullmatch(root["reset_commitment_sha256"]) is None
    ):
        _fail("recipe_binding_invalid")
    _integer(
        root["timeout_milliseconds"], 1, MAX_TIMEOUT_MILLISECONDS
    )
    steps = root["steps"]
    if type(steps) is not list or not 2 <= len(steps) <= MAX_STEPS:
        _fail("recipe_steps_invalid")
    ids: set[str] = set()
    send_total = 0
    expect_total = 0
    first_send_index: int | None = None
    last_expect_index: int | None = None
    for index, item in enumerate(steps):
        if type(item) is not dict:
            _fail("recipe_step_invalid")
        step_id = item.get("id")
        if (
            type(step_id) is not str
            or _SAFE_STEP_ID.fullmatch(step_id) is None
            or step_id in ids
        ):
            _fail("recipe_step_id_invalid")
        ids.add(step_id)
        if item.get("op") == "send":
            raw = _mapping(item, _SEND_KEYS)
            send_total += len(_literal(raw["data"]))
            if first_send_index is None:
                first_send_index = index
        elif item.get("op") == "expect":
            raw = _mapping(item, _EXPECT_KEYS)
            expected = _literal(raw["data"])
            if raw["stream"] not in {"stdout", "stderr"}:
                _fail("recipe_stream_invalid")
            expect_total += _integer(
                raw["max_read_bytes"], len(expected), MAX_STEP_BYTES
            )
            last_expect_index = index
        else:
            _fail("recipe_operation_invalid")
        if send_total > MAX_AGGREGATE_SEND_BYTES:
            _fail("recipe_send_limit")
        if expect_total > MAX_AGGREGATE_EXPECT_BYTES:
            _fail("recipe_expect_limit")
    if (
        first_send_index is None
        or last_expect_index is None
        or last_expect_index <= first_send_index
        or steps[-1].get("op") != "expect"
    ):
        _fail("recipe_control_unobservable")
    return root


def _positive_int(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected integer") from error
    if parsed < 1:
        raise argparse.ArgumentTypeError("expected positive integer")
    return parsed


def _nonnegative_int(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected integer") from error
    if parsed < 0:
        raise argparse.ArgumentTypeError("expected nonnegative integer")
    return parsed


def _digest(value: str) -> str:
    if _SHA256.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("expected lowercase SHA-256")
    return value


def _image_digest(value: str) -> str:
    if _IMAGE_DIGEST.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("expected pinned image digest")
    return value


def _safe_id(value: str) -> str:
    if _SAFE_ID.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("expected safe identifier")
    return value


def _args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run one bounded local data transcript replay."
    )
    parser.add_argument("--peer", type=Path, required=True)
    parser.add_argument("--peer-data", type=Path, required=True)
    parser.add_argument("--recipe", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, default=Path("/work"))
    parser.add_argument("--category", choices=("crypto", "misc"), required=True)
    parser.add_argument(
        "--phase", choices=("positive", "control"), required=True
    )
    parser.add_argument("--ordinal", type=_positive_int, required=True)
    parser.add_argument("--preissue-id", type=_safe_id, required=True)
    parser.add_argument("--preissue-sha256", type=_digest, required=True)
    parser.add_argument("--producer-sha256", type=_digest, required=True)
    parser.add_argument("--recipe-sha256", type=_digest, required=True)
    parser.add_argument("--recipe-size-bytes", type=_positive_int, required=True)
    parser.add_argument("--peer-sha256", type=_digest, required=True)
    parser.add_argument("--peer-size-bytes", type=_positive_int, required=True)
    parser.add_argument("--peer-data-sha256", type=_digest, required=True)
    parser.add_argument(
        "--peer-data-size-bytes", type=_nonnegative_int, required=True
    )
    parser.add_argument(
        "--reset-commitment-sha256", type=_digest, required=True
    )
    parser.add_argument("--image-digest", type=_image_digest, required=True)
    parser.add_argument(
        "--configuration-epoch", type=_nonnegative_int, required=True
    )
    parsed = parser.parse_args(argv)
    if parsed.ordinal not in {1, 2, 3}:
        parser.error("--ordinal must be 1, 2, or 3")
    return parsed


def _open_regular(
    path: Path,
    *,
    maximum: int,
    expected_sha256: str,
    expected_size: int,
    executable: bool = False,
) -> tuple[int, bytes]:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ProducerError("bound_input_unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            stat.S_ISREG(metadata.st_mode) is False
            or metadata.st_size != expected_size
            or not 0 <= metadata.st_size <= maximum
            or (executable and metadata.st_mode & 0o111 == 0)
        ):
            _fail("bound_input_invalid")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            payload = stream.read(maximum + 1)
        if (
            len(payload) != expected_size
            or len(payload) > maximum
            or _sha256(payload) != expected_sha256
        ):
            _fail("bound_input_changed")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor, payload
    except BaseException:
        os.close(descriptor)
        raise


def _read_regular(
    path: Path,
    *,
    maximum: int,
    expected_sha256: str,
    expected_size: int,
) -> bytes:
    descriptor, payload = _open_regular(
        path,
        maximum=maximum,
        expected_sha256=expected_sha256,
        expected_size=expected_size,
    )
    os.close(descriptor)
    return payload


def _reset_descriptor(args: argparse.Namespace) -> dict[str, object]:
    return {
        "category": args.category,
        "control_mutation": CONTROL_MUTATION,
        "execution": "direct_execve_peer_with_fresh_state_argv_v1",
        "network": "none",
        "peer": {
            "sha256": args.peer_sha256,
            "size_bytes": args.peer_size_bytes,
        },
        "peer_data": {
            "sha256": args.peer_data_sha256,
            "size_bytes": args.peer_data_size_bytes,
        },
        "reset_mode": RESET_MODE,
        "schema_version": SCHEMA_VERSION,
    }


def _write_exclusive(path: Path, payload: bytes) -> None:
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_CLOEXEC
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        raise ProducerError("artifact_write_failed") from error


def _preexec() -> None:
    os.setsid()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (125, 125))
    resource.setrlimit(
        resource.RLIMIT_AS, (1024 * 1024 * 1024, 1024 * 1024 * 1024)
    )
    resource.setrlimit(
        resource.RLIMIT_FSIZE, (2 * 1024 * 1024, 2 * 1024 * 1024)
    )
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    if hasattr(resource, "RLIMIT_NPROC"):
        resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))


def _terminate_group(process: subprocess.Popen[bytes]) -> bool:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=0.25)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            return False
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return True
    for _attempt in range(20):
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.01)
    return False


class Replay:
    def __init__(
        self,
        process: subprocess.Popen[bytes],
        *,
        deadline: float,
        binding: Mapping[str, object],
    ) -> None:
        self.process = process
        self.deadline = deadline
        self.binding = binding
        self.selector = selectors.DefaultSelector()
        assert process.stdout is not None
        assert process.stderr is not None
        assert process.stdin is not None
        for stream, name in (
            (process.stdout, "stdout"),
            (process.stderr, "stderr"),
        ):
            os.set_blocking(stream.fileno(), False)
            self.selector.register(
                stream,
                selectors.EVENT_READ,
                name,
            )
        os.set_blocking(process.stdin.fileno(), False)
        self.streams = {
            "stdin": bytearray(),
            "stdout": bytearray(),
            "stderr": bytearray(),
        }
        self.events: list[dict[str, object]] = []
        self.truncated = False
        self.timed_out = False

    def close(self) -> None:
        self.selector.close()

    def _remaining(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            self.timed_out = True
            return 0.0
        return remaining

    def _event(
        self,
        *,
        direction: str,
        stream: str,
        data: bytes,
        step_id: str | None,
    ) -> None:
        current = self.streams[stream]
        maximum = (
            MAX_AGGREGATE_SEND_BYTES
            if stream == "stdin"
            else MAX_STREAM_BYTES
        )
        if len(current) + len(data) > maximum:
            self.truncated = True
            return
        offset = len(current)
        current.extend(data)
        self.events.append(
            {
                "data_hex": data.hex(),
                "direction": direction,
                "offset": offset,
                "sequence": len(self.events) + 1,
                "sha256": _sha256(data),
                "size_bytes": len(data),
                "step_id": step_id,
                "stream": stream,
            }
        )

    def _read_ready(
        self,
        file_object: Any,
        stream: str,
        *,
        limit: int = MAX_STEP_BYTES,
        step_id: str | None = None,
        aggregate: bytearray | None = None,
    ) -> bool:
        try:
            chunk = os.read(file_object.fileno(), max(1, limit))
        except BlockingIOError:
            return True
        if not chunk:
            try:
                self.selector.unregister(file_object)
            except (KeyError, ValueError):
                pass
            return False
        if aggregate is None:
            self._event(
                direction="receive",
                stream=stream,
                data=chunk,
                step_id=step_id,
            )
        else:
            aggregate.extend(chunk)
        return True

    def _drain_other_events(
        self,
        ready: list[tuple[selectors.SelectorKey, int]],
        *,
        target_stream: str | None = None,
        target_step_id: str | None = None,
        target_bytes: bytearray | None = None,
        target_limit: int = MAX_STEP_BYTES,
    ) -> bool | None:
        target_open: bool | None = None
        for key, mask in ready:
            name = key.data
            if name == "stdin" or not mask & selectors.EVENT_READ:
                continue
            if name == target_stream and target_bytes is not None:
                target_open = self._read_ready(
                    key.fileobj,
                    name,
                    limit=max(1, target_limit - len(target_bytes)),
                    step_id=target_step_id,
                    aggregate=target_bytes,
                )
            else:
                self._read_ready(key.fileobj, name)
        return target_open

    def send(self, step_id: str, data: bytes) -> bool:
        assert self.process.stdin is not None
        try:
            self.selector.register(
                self.process.stdin, selectors.EVENT_WRITE, "stdin"
            )
        except KeyError:
            pass
        offset = 0
        try:
            while offset < len(data) and not self.truncated:
                remaining = self._remaining()
                if remaining <= 0:
                    return False
                ready = self.selector.select(remaining)
                if not ready:
                    self.timed_out = True
                    return False
                self._drain_other_events(ready)
                for key, mask in ready:
                    if (
                        key.data != "stdin"
                        or not mask & selectors.EVENT_WRITE
                    ):
                        continue
                    try:
                        written = os.write(
                            key.fileobj.fileno(), data[offset:]
                        )
                    except (BrokenPipeError, BlockingIOError):
                        written = 0
                    if written > 0:
                        offset += written
        finally:
            try:
                self.selector.unregister(self.process.stdin)
            except (KeyError, ValueError):
                pass
        if offset != len(data):
            return False
        self._event(
            direction="send",
            stream="stdin",
            data=data,
            step_id=step_id,
        )
        return not self.truncated

    def expect(
        self,
        step_id: str,
        stream: str,
        expected: bytes,
        maximum: int,
    ) -> tuple[bool, bool]:
        observed = bytearray()
        target_open = True
        mismatch = False
        while (
            len(observed) < len(expected)
            and target_open
            and not self.truncated
        ):
            remaining = self._remaining()
            if remaining <= 0:
                break
            ready = self.selector.select(remaining)
            if not ready:
                self.timed_out = True
                break
            target_result = self._drain_other_events(
                ready,
                target_stream=stream,
                target_step_id=step_id,
                target_bytes=observed,
                target_limit=min(maximum, len(expected)),
            )
            if target_result is not None:
                target_open = target_result
            if bytes(observed) != expected[: len(observed)]:
                mismatch = True
                break
        actual = bytes(observed)
        self._event(
            direction="receive",
            stream=stream,
            data=actual,
            step_id=step_id,
        )
        if self.timed_out or self.truncated:
            return False, False
        byte_mismatch = mismatch or any(
            actual_byte != expected_byte
            for actual_byte, expected_byte in zip(
                actual, expected, strict=False
            )
        )
        return actual == expected, byte_mismatch

    def finish(self) -> bool:
        assert self.process.stdin is not None
        try:
            self.selector.unregister(self.process.stdin)
        except (KeyError, ValueError):
            pass
        try:
            self.process.stdin.close()
        except BrokenPipeError:
            pass
        while self.process.poll() is None and not self.truncated:
            remaining = self._remaining()
            if remaining <= 0:
                break
            ready = self.selector.select(min(remaining, 0.1))
            if ready:
                self._drain_other_events(ready)
        if self.process.poll() is None:
            self.timed_out = True
            return False
        for _attempt in range(4):
            ready = self.selector.select(0)
            if not ready:
                break
            self._drain_other_events(ready)
        return not self.timed_out and not self.truncated


def _binding(args: argparse.Namespace) -> dict[str, object]:
    return {
        "category": args.category,
        "configuration_epoch": args.configuration_epoch,
        "image_digest": args.image_digest,
        "network": "none",
        "ordinal": args.ordinal,
        "peer_data_sha256": args.peer_data_sha256,
        "peer_data_size_bytes": args.peer_data_size_bytes,
        "peer_sha256": args.peer_sha256,
        "peer_size_bytes": args.peer_size_bytes,
        "phase": args.phase,
        "preissue_id": args.preissue_id,
        "preissue_sha256": args.preissue_sha256,
        "producer_sha256": args.producer_sha256,
        "recipe_sha256": args.recipe_sha256,
        "recipe_size_bytes": args.recipe_size_bytes,
        "reset_commitment_sha256": args.reset_commitment_sha256,
    }


def _run(args: argparse.Namespace) -> tuple[dict[str, object], int]:
    peer_payload = _read_regular(
        args.peer,
        maximum=MAX_PEER_BYTES,
        expected_sha256=args.peer_sha256,
        expected_size=args.peer_size_bytes,
    )
    peer_data = _read_regular(
        args.peer_data,
        maximum=MAX_PEER_DATA_BYTES,
        expected_sha256=args.peer_data_sha256,
        expected_size=args.peer_data_size_bytes,
    )
    recipe_payload = _read_regular(
        args.recipe,
        maximum=MAX_RECIPE_BYTES,
        expected_sha256=args.recipe_sha256,
        expected_size=args.recipe_size_bytes,
    )
    recipe = _parse_recipe(recipe_payload)
    if (
        recipe["category"] != args.category
        or recipe["preissue_id"] != args.preissue_id
        or recipe["reset_commitment_sha256"]
        != args.reset_commitment_sha256
        or _sha256(_canonical(_reset_descriptor(args)))
        != args.reset_commitment_sha256
    ):
        _fail("preissue_binding_mismatch")
    del peer_payload

    relative = Path(
        ".ctf/data-transcript-v1"
    ) / args.preissue_id / args.recipe_sha256 / (
        f"{args.phase}-{args.ordinal}"
    )
    output = args.work_root / relative
    try:
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
    except OSError as error:
        raise ProducerError("output_scope_invalid") from error
    state_path = output / "peer-state.bin"
    _write_exclusive(state_path, peer_data)
    initial_state = _read_regular(
        state_path,
        maximum=MAX_PEER_DATA_BYTES,
        expected_sha256=args.peer_data_sha256,
        expected_size=args.peer_data_size_bytes,
    )
    del initial_state
    nonce_sha256 = _sha256(secrets.token_bytes(32))
    reset_binding = {
        "category": args.category,
        "ordinal": args.ordinal,
        "phase": args.phase,
        "preissue_id": args.preissue_id,
        "reset_commitment_sha256": args.reset_commitment_sha256,
    }
    reset_proof = _canonical(
        {
            "binding": reset_binding,
            "fresh_instance_nonce_sha256": nonce_sha256,
            "fresh_state_initial_sha256": args.peer_data_sha256,
            "peer_data_sha256": args.peer_data_sha256,
            "peer_sha256": args.peer_sha256,
            "protocol": "ctfos.data_transcript.reset_proof.v1",
            "schema_version": 1,
        }
    )

    started = time.monotonic()
    timeout_ms = int(recipe["timeout_milliseconds"])
    deadline = started + timeout_ms / 1000.0
    peer_descriptor, peer_payload = _open_regular(
        args.peer,
        maximum=MAX_PEER_BYTES,
        expected_sha256=args.peer_sha256,
        expected_size=args.peer_size_bytes,
        executable=True,
    )
    del peer_payload
    try:
        peer_exec_path = f"/proc/self/fd/{peer_descriptor}"
        process = subprocess.Popen(
            [peer_exec_path, str(state_path)],
            executable=peer_exec_path,
            cwd=output,
            env=_FIXED_ENV,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            pass_fds=(peer_descriptor,),
            preexec_fn=_preexec,
        )
    except (OSError, ValueError) as error:
        raise ProducerError("peer_launch_failed") from error
    finally:
        os.close(peer_descriptor)

    replay = Replay(process, deadline=deadline, binding=reset_binding)
    mismatch_step: str | None = None
    completed = True
    first_send = True
    mutation_step: str | None = None
    try:
        for raw_step in recipe["steps"]:
            step_id = str(raw_step["id"])
            if raw_step["op"] == "send":
                data = _literal(raw_step["data"])
                if first_send:
                    first_send = False
                    if args.phase == "control":
                        mutated = bytearray(data)
                        mutated[0] ^= 1 << (args.ordinal - 1)
                        data = bytes(mutated)
                        mutation_step = step_id
                if not replay.send(step_id, data):
                    completed = False
                    break
            else:
                matched, rejected = replay.expect(
                    step_id,
                    str(raw_step["stream"]),
                    _literal(raw_step["data"]),
                    int(raw_step["max_read_bytes"]),
                )
                if not matched:
                    completed = False
                    if rejected:
                        mismatch_step = step_id
                    break
        if completed:
            completed = replay.finish()
    finally:
        process_group_cleaned = _terminate_group(process)
        replay.close()

    if replay.timed_out:
        status = "unverifiable"
        reason = "peer_timeout"
    elif replay.truncated:
        status = "unverifiable"
        reason = "stream_truncated"
    elif args.phase == "positive":
        if completed and mismatch_step is None:
            status = "matched"
            reason = "all_steps_matched"
        else:
            status = "failed"
            reason = "recipe_expectation_mismatch"
    elif mismatch_step is not None:
        status = "rejected"
        reason = "control_mutation_rejected"
    else:
        status = "failed"
        reason = "control_mutation_accepted"

    transcript = _canonical(
        {
            "binding": {
                "category": args.category,
                "ordinal": args.ordinal,
                "phase": args.phase,
                "preissue_id": args.preissue_id,
                "recipe_sha256": args.recipe_sha256,
                "reset_commitment_sha256": (
                    args.reset_commitment_sha256
                ),
            },
            "events": replay.events,
            "schema_version": 1,
        }
    )
    if len(transcript) > MAX_TRANSCRIPT_BYTES:
        status = "unverifiable"
        reason = "transcript_truncated"
        replay.truncated = True
    stdout = bytes(replay.streams["stdout"])
    stderr = bytes(replay.streams["stderr"])
    stdout_path = relative / "peer.stdout.bin"
    stderr_path = relative / "peer.stderr.bin"
    transcript_path = relative / "transcript.json"
    reset_path = relative / "reset-proof.json"
    _write_exclusive(args.work_root / stdout_path, stdout)
    _write_exclusive(args.work_root / stderr_path, stderr)
    _write_exclusive(args.work_root / transcript_path, transcript)
    _write_exclusive(args.work_root / reset_path, reset_proof)
    return_code = process.returncode
    exit_code = (
        return_code
        if type(return_code) is int and return_code >= 0
        else None
    )
    peer_signal = (
        -return_code
        if type(return_code) is int and return_code < 0
        else None
    )
    observation = {
        "control_mutation_applied": args.phase == "control",
        "control_mutation_step_id": mutation_step,
        "elapsed_milliseconds": min(
            125_000, int((time.monotonic() - started) * 1000)
        ),
        "fresh_instance_nonce_sha256": nonce_sha256,
        "fresh_state_initial_sha256": args.peer_data_sha256,
        "mismatch_step_id": mismatch_step,
        "peer_exit_code": exit_code,
        "peer_signal": peer_signal,
        "process_group_cleaned": process_group_cleaned,
        "reset_proof_path": reset_path.as_posix(),
        "reset_proof_sha256": _sha256(reset_proof),
        "reset_proof_size_bytes": len(reset_proof),
        "stderr_path": stderr_path.as_posix(),
        "stderr_sha256": _sha256(stderr),
        "stderr_size_bytes": len(stderr),
        "stdout_path": stdout_path.as_posix(),
        "stdout_sha256": _sha256(stdout),
        "stdout_size_bytes": len(stdout),
        "timed_out": replay.timed_out,
        "transcript_path": transcript_path.as_posix(),
        "transcript_sha256": _sha256(transcript),
        "transcript_size_bytes": len(transcript),
        "truncated": replay.truncated,
    }
    document = {
        "binding": _binding(args),
        "contract": {
            "id": PRODUCER_CONTRACT_ID,
            "protocol": PRODUCER_PROTOCOL,
            "recipe_contract_fingerprint": RECIPE_CONTRACT_FINGERPRINT,
            "version": PRODUCER_CONTRACT_VERSION,
        },
        "observation": observation,
        "reason_code": reason,
        "schema_version": SCHEMA_VERSION,
        "status": status,
    }
    encoded = _canonical(document)
    if len(encoded) > MAX_RESULT_BYTES:
        _fail("result_size_limit")
    return document, 0 if status in {"matched", "rejected"} else 1


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _args(argv)
        document, code = _run(args)
    except ProducerError as error:
        print(error.code, file=sys.stderr)
        return 2
    sys.stdout.buffer.write(_canonical(document))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
