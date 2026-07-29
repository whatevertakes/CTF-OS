#!/usr/bin/env python3
"""Noninteractive HTTP request starter for web challenges."""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import stat
import sys
import time
from pathlib import Path
from typing import Iterable

import chardet
import requests
from safe_output import atomic_write, open_output_dir

OUTPUT_DIR = Path("/work/web")
HARD_MAX_BYTES = 256 * 1024 * 1024
HARD_MAX_REQUEST_BYTES = 64 * 1024 * 1024
HARD_MAX_DEADLINE = 300.0


class RequestDeadlineExceeded(TimeoutError):
    pass


def header(value: str) -> tuple[str, str]:
    if ":" not in value:
        raise argparse.ArgumentTypeError("header must use NAME: VALUE")
    name, raw_value = value.split(":", 1)
    name = name.strip()
    if not name:
        raise argparse.ArgumentTypeError("header name cannot be empty")
    return name, raw_value.strip()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send one bounded HTTP request and save its response under /work/web."
    )
    parser.add_argument("url", help="absolute http:// or https:// URL")
    parser.add_argument(
        "-X",
        "--method",
        default="GET",
        choices=("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"),
    )
    parser.add_argument(
        "-H", "--header", action="append", default=[], type=header, metavar="NAME: VALUE"
    )
    body = parser.add_mutually_exclusive_group()
    body.add_argument("--data", help="literal request body")
    body.add_argument("--data-file", type=Path, help="request body file, normally in /challenge")
    parser.add_argument(
        "--max-request-bytes",
        type=int,
        default=16 * 1024 * 1024,
        help="maximum data-file bytes (default: 16 MiB, max: 64 MiB)",
    )
    parser.add_argument("--follow", action="store_true", help="follow redirects")
    parser.add_argument("--insecure", action="store_true", help="disable TLS verification")
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="monotonic whole-request deadline in seconds (default: 15, max: 300)",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=16 * 1024 * 1024,
        help="maximum response bytes to retain (default: 16 MiB)",
    )
    args = parser.parse_args()
    if not args.url.startswith(("http://", "https://")):
        parser.error("url must start with http:// or https://")
    if not 0.1 <= args.timeout <= HARD_MAX_DEADLINE:
        parser.error("--timeout must be between 0.1 and 300 seconds")
    if not 1 <= args.max_bytes <= HARD_MAX_BYTES:
        parser.error("--max-bytes must be between 1 byte and 256 MiB")
    if not 1 <= args.max_request_bytes <= HARD_MAX_REQUEST_BYTES:
        parser.error("--max-request-bytes must be between 1 byte and 64 MiB")
    if args.data_file is not None and not args.data_file.is_file():
        parser.error(f"request body file does not exist: {args.data_file}")
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
            raise OSError("request body is not a regular file")
        if file_stat.st_size > limit:
            raise ValueError(f"request body size {file_stat.st_size} exceeds {limit}")
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(descriptor, min(1024 * 1024, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > limit:
            raise ValueError(f"request body grew beyond {limit} bytes")
        return bytes(data)
    finally:
        os.close(descriptor)


def read_limited(
    chunks: Iterable[bytes], limit: int, deadline: float
) -> tuple[bytes, bool]:
    body = bytearray()
    truncated = False
    for chunk in chunks:
        if time.monotonic() >= deadline:
            raise RequestDeadlineExceeded("whole-request deadline exceeded")
        if not chunk:
            continue
        remaining = limit - len(body)
        if remaining <= 0:
            truncated = True
            break
        body.extend(chunk[:remaining])
        if len(chunk) > remaining:
            truncated = True
            break
    return bytes(body), truncated


def choose_encoding(response: requests.Response, body: bytes) -> str:
    content_type = response.headers.get("content-type", "")
    match = re.search(r"charset\s*=\s*[\"']?([^;\"'\s]+)", content_type, re.IGNORECASE)
    if match:
        return match.group(1)
    detected = chardet.detect(body)
    return str(detected.get("encoding") or "utf-8")


def main() -> int:
    args = parse_args()
    request_headers = dict(args.header)
    request_body: bytes | str | None = args.data
    try:
        output_descriptor = open_output_dir(OUTPUT_DIR)
    except OSError as exc:
        print(
            json.dumps(
                {"ok": False, "error": "UnsafeOutputDirectory", "message": str(exc)}
            )
        )
        return 2
    if args.data_file is not None:
        try:
            request_body = read_regular_bounded(
                args.data_file, args.max_request_bytes
            )
        except (OSError, ValueError) as exc:
            error = {
                "ok": False,
                "error": "InvalidRequestBody",
                "message": str(exc),
                "max_request_bytes": args.max_request_bytes,
            }
            atomic_write(
                output_descriptor,
                "error.json",
                (json.dumps(error, ensure_ascii=False, indent=2) + "\n").encode(
                    "utf-8"
                ),
            )
            print(json.dumps(error, ensure_ascii=False))
            return 2
    started = time.monotonic()
    deadline = started + args.timeout
    previous_alarm_handler = signal.getsignal(signal.SIGALRM)

    def deadline_alarm(_signum: int, _frame: object) -> None:
        raise RequestDeadlineExceeded("whole-request deadline exceeded")

    signal.signal(signal.SIGALRM, deadline_alarm)
    signal.setitimer(signal.ITIMER_REAL, args.timeout)
    try:
        with requests.Session() as session:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RequestDeadlineExceeded("whole-request deadline exceeded")
            with session.request(
                args.method,
                args.url,
                headers=request_headers,
                data=request_body,
                allow_redirects=args.follow,
                timeout=(remaining, remaining),
                verify=not args.insecure,
                stream=True,
            ) as response:
                raw_body, truncated = read_limited(
                    response.iter_content(chunk_size=64 * 1024),
                    args.max_bytes,
                    deadline,
                )
    except RequestDeadlineExceeded as exc:
        signal.setitimer(signal.ITIMER_REAL, 0)
        error = {
            "ok": False,
            "error": "RequestDeadlineExceeded",
            "message": str(exc),
            "deadline_seconds": args.timeout,
            "elapsed_seconds": round(time.monotonic() - started, 6),
        }
        atomic_write(
            output_descriptor,
            "error.json",
            (json.dumps(error, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
        )
        print(json.dumps(error, ensure_ascii=False))
        return 2
    except requests.RequestException as exc:
        signal.setitimer(signal.ITIMER_REAL, 0)
        if time.monotonic() >= deadline:
            error = {
                "ok": False,
                "error": "RequestDeadlineExceeded",
                "message": "whole-request deadline exceeded",
                "deadline_seconds": args.timeout,
                "elapsed_seconds": round(time.monotonic() - started, 6),
            }
        else:
            error = {"ok": False, "error": type(exc).__name__, "message": str(exc)}
        atomic_write(
            output_descriptor,
            "error.json",
            (json.dumps(error, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
        )
        print(json.dumps(error, ensure_ascii=False))
        return 2
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_alarm_handler)

    encoding = choose_encoding(response, raw_body)
    try:
        decoded = raw_body.decode(encoding, errors="replace")
    except LookupError:
        encoding = "utf-8"
        decoded = raw_body.decode(encoding, errors="replace")
    atomic_write(output_descriptor, "body.bin", raw_body)
    atomic_write(output_descriptor, "body.txt", decoded.encode("utf-8"))

    metadata = {
        "ok": True,
        "request": {"method": args.method, "url": args.url},
        "deadline_seconds": args.timeout,
        "elapsed_seconds": round(time.monotonic() - started, 6),
        "response": {
            "status": response.status_code,
            "reason": response.reason,
            "url": response.url,
            "headers": dict(response.headers),
            "history": [
                {"status": item.status_code, "url": item.url} for item in response.history
            ],
            "encoding": encoding,
            "saved_bytes": len(raw_body),
            "truncated": truncated,
        },
        "files": {
            "body": str(OUTPUT_DIR / "body.bin"),
            "text": str(OUTPUT_DIR / "body.txt"),
            "metadata": str(OUTPUT_DIR / "response.json"),
        },
    }
    atomic_write(
        output_descriptor,
        "response.json",
        (json.dumps(metadata, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
    )
    print(json.dumps(metadata, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
