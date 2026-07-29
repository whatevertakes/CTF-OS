#!/usr/bin/env python3
"""Minimal noninteractive pwntools starter.

Copy this file to /work and replace build_payload() and the receive sequence with
the challenge-specific exploit.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import time
from pathlib import Path

from pwn import ELF, context, process, remote
from safe_output import atomic_write, open_output_dir

OUTPUT_DIR = Path("/work/pwn")
FLAG_RE = re.compile(rb"[A-Za-z0-9_]{2,20}\{[^}\r\n]{1,200}\}")
HARD_MAX_PAYLOAD_BYTES = 64 * 1024 * 1024
HARD_MAX_TRANSCRIPT_BYTES = 256 * 1024 * 1024
HARD_MAX_WAIT = 300.0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a local binary or remote pwntools tube without interactive stdin."
    )
    parser.add_argument("binary", type=Path, help="challenge ELF, normally under /challenge")
    parser.add_argument("--host", help="remote host")
    parser.add_argument("--port", type=int, help="remote TCP port")
    parser.add_argument("--payload-file", type=Path, help="bytes to send after connecting")
    parser.add_argument("--send-line", action="store_true", help="append a newline to the payload")
    parser.add_argument(
        "--wait",
        type=float,
        default=2.0,
        help="connect timeout and monotonic transcript deadline (default: 2s, max: 300s)",
    )
    parser.add_argument(
        "--max-payload-bytes",
        type=int,
        default=4 * 1024 * 1024,
        help="maximum payload-file bytes (default: 4 MiB, max: 64 MiB)",
    )
    parser.add_argument(
        "--max-transcript-bytes",
        type=int,
        default=16 * 1024 * 1024,
        help="maximum received transcript bytes (default: 16 MiB, max: 256 MiB)",
    )
    args = parser.parse_args()
    if not args.binary.is_file():
        parser.error(f"binary does not exist: {args.binary}")
    if (args.host is None) != (args.port is None):
        parser.error("--host and --port must be supplied together")
    if args.port is not None and not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if args.payload_file is not None and not args.payload_file.is_file():
        parser.error(f"payload file does not exist: {args.payload_file}")
    if not 0.1 <= args.wait <= HARD_MAX_WAIT:
        parser.error("--wait must be between 0.1 and 300 seconds")
    if not 1 <= args.max_payload_bytes <= HARD_MAX_PAYLOAD_BYTES:
        parser.error("--max-payload-bytes must be between 1 byte and 64 MiB")
    if not 1 <= args.max_transcript_bytes <= HARD_MAX_TRANSCRIPT_BYTES:
        parser.error("--max-transcript-bytes must be between 1 byte and 256 MiB")
    return args


def read_regular_bounded(path: Path, limit: int) -> bytes:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(path, flags)
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise OSError("payload is not a regular file")
        if file_stat.st_size > limit:
            raise ValueError(f"payload size {file_stat.st_size} exceeds {limit}")
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(descriptor, min(1024 * 1024, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > limit:
            raise ValueError(f"payload grew beyond {limit} bytes")
        return bytes(data)
    finally:
        os.close(descriptor)


def build_payload(args: argparse.Namespace, elf: ELF) -> bytes:
    """Replace this with the challenge-specific payload construction."""
    del elf
    return (
        read_regular_bounded(args.payload_file, args.max_payload_bytes)
        if args.payload_file
        else b""
    )


def receive_bounded(tube: object, limit: int, seconds: float) -> tuple[bytes, bool, bool]:
    deadline = time.monotonic() + seconds
    transcript = bytearray()
    size_truncated = False
    deadline_reached = False
    while len(transcript) <= limit:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            deadline_reached = True
            break
        try:
            chunk = tube.recv(
                numb=min(64 * 1024, limit + 1 - len(transcript)),
                timeout=remaining,
            )
        except EOFError:
            break
        if not chunk:
            if time.monotonic() >= deadline:
                deadline_reached = True
            break
        transcript.extend(chunk)
        if len(transcript) > limit:
            size_truncated = True
            del transcript[limit:]
            break
    return bytes(transcript), size_truncated, deadline_reached


def main() -> int:
    args = parse_args()
    try:
        output_descriptor = open_output_dir(OUTPUT_DIR)
    except OSError as exc:
        print(
            json.dumps(
                {"ok": False, "error": "UnsafeOutputDirectory", "message": str(exc)}
            )
        )
        return 1
    context.log_level = "error"
    context.timeout = args.wait
    tube = None
    transcript = b""
    transcript_truncated = False
    deadline_reached = False
    try:
        elf = ELF(str(args.binary.resolve()), checksec=False)
        if args.host is None:
            tube = process([str(args.binary.resolve())])
        else:
            tube = remote(args.host, args.port, timeout=args.wait)

        payload = build_payload(args, elf)
        if payload:
            tube.sendline(payload) if args.send_line else tube.send(payload)

        # Replace recvrepeat() with sendafter()/recvuntil() steps for the target.
        transcript, transcript_truncated, deadline_reached = receive_bounded(
            tube, args.max_transcript_bytes, args.wait
        )
    except Exception as exc:
        error = {"ok": False, "error": type(exc).__name__, "message": str(exc)}
        atomic_write(
            output_descriptor,
            "error.json",
            (json.dumps(error, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
        )
        print(json.dumps(error, ensure_ascii=False))
        return 1
    finally:
        if tube is not None:
            tube.close()

    transcript_path = OUTPUT_DIR / "transcript.bin"
    atomic_write(output_descriptor, "transcript.bin", transcript)
    flags = [item.decode("utf-8", errors="replace") for item in FLAG_RE.findall(transcript)]
    result = {
        "ok": True,
        "mode": "remote" if args.host else "local",
        "received_bytes": len(transcript),
        "max_transcript_bytes": args.max_transcript_bytes,
        "transcript_truncated": transcript_truncated,
        "transcript_deadline_seconds": args.wait,
        "deadline_reached": deadline_reached,
        "flags": flags,
        "transcript": str(transcript_path),
    }
    atomic_write(
        output_descriptor,
        "result.json",
        (json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
    )
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
