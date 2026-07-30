#!/usr/bin/env python3
"""Bounded race and challenge-scoped OOB Web transport helper.

The helper runs only behind the engine's private Web-session mount.  Cookie
values stay in that mount and are redacted from every public response body.
The public report contains request/response hashes, aggregate timing, cookie
transition names, and callback hashes; it never contains a cookie value.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Mapping
from urllib.parse import urlsplit

import requests
from safe_output import atomic_write, open_output_dir
from session_state import (
    PersistentWebSession,
    SESSION_NAMES,
    WebSessionStateError,
    engine_private_roots,
    normalize_cookies,
    redact_cookie_bytes,
)


OUTPUT_DIR = Path("/work/web-active")
PROTOCOL = "ctfos.web.active_probe.helper.v1"
MAX_BODY_BYTES = 16 * 1024 * 1024
MAX_CALLBACK_BYTES = 8 * 1024 * 1024
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_CONCURRENCY = 32
MAX_ATTEMPTS = 16
MAX_REQUESTS = 256
MAX_CALLBACKS = 8
CALLBACK_PLACEHOLDER = b"{{CTF_OOB_URL}}"


class ActiveProbeError(RuntimeError):
    """Stable helper error without target-controlled message text."""


class _ResponseBudget:
    """One invocation-wide byte budget shared by concurrent readers."""

    def __init__(self, maximum: int) -> None:
        self.maximum = maximum
        self._consumed = 0
        self._lock = threading.Lock()

    @property
    def consumed(self) -> int:
        with self._lock:
            return self._consumed

    def consume(self, amount: int) -> None:
        if amount < 0:
            raise ActiveProbeError("response_budget_invalid")
        with self._lock:
            if self._consumed + amount > self.maximum:
                raise ActiveProbeError(
                    "aggregate_response_size_exceeded"
                )
            self._consumed += amount


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_bytes(value: object) -> bytes:
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


def _read_bounded(path: Path, maximum: int) -> bytes:
    import os
    import stat

    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > maximum
        ):
            raise ActiveProbeError("input_not_bounded_regular")
        payload = bytearray()
        while len(payload) <= maximum:
            block = os.read(
                descriptor,
                min(1024 * 1024, maximum + 1 - len(payload)),
            )
            if not block:
                break
            payload.extend(block)
        after = os.fstat(descriptor)
        if (
            len(payload) > maximum
            or (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            )
        ):
            raise ActiveProbeError("input_changed_while_reading")
        return bytes(payload)
    finally:
        os.close(descriptor)


def _validate_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or len(value.encode("utf-8")) > 16 * 1024
    ):
        raise ActiveProbeError("target_url_invalid")
    return value


def _load_requests_cookies(
    session: requests.Session,
    cookies: list[dict[str, object]],
) -> None:
    for cookie in cookies:
        rest: dict[str, object] = {}
        if cookie["http_only"]:
            rest["HttpOnly"] = True
        if cookie["same_site"] is not None:
            rest["SameSite"] = cookie["same_site"]
        session.cookies.set_cookie(
            requests.cookies.create_cookie(
                name=str(cookie["name"]),
                value=str(cookie["value"]),
                domain=str(cookie["domain"]),
                path=str(cookie["path"]),
                secure=bool(cookie["secure"]),
                expires=(
                    int(float(cookie["expires"]))
                    if cookie["expires"] is not None
                    else None
                ),
                rest=rest,
            )
        )


def _dump_requests_cookies(
    session: requests.Session,
) -> list[dict[str, object]]:
    values: list[dict[str, object]] = []
    for cookie in session.cookies:
        rest = getattr(cookie, "_rest", {})
        values.append(
            {
                "domain": cookie.domain,
                "expires": cookie.expires,
                "http_only": (
                    isinstance(rest, dict) and "HttpOnly" in rest
                ),
                "name": cookie.name,
                "path": cookie.path,
                "same_site": (
                    rest.get("SameSite")
                    if isinstance(rest, dict)
                    else None
                ),
                "secure": cookie.secure,
                "value": cookie.value,
            }
        )
    return normalize_cookies(values)


def _read_response(
    response: requests.Response,
    *,
    maximum: int,
    deadline: float,
    budget: _ResponseBudget,
) -> tuple[bytes, bool]:
    payload = bytearray()
    truncated = False
    for block in response.iter_content(chunk_size=64 * 1024):
        if time.monotonic() >= deadline:
            raise ActiveProbeError("probe_deadline_exceeded")
        if not block:
            continue
        remaining = maximum - len(payload)
        if remaining <= 0:
            truncated = True
            break
        accepted = block[:remaining]
        budget.consume(len(accepted))
        payload.extend(accepted)
        if len(accepted) < len(block):
            truncated = True
            break
    return bytes(payload), truncated


def _cookie_key(
    cookie: Mapping[str, object],
) -> tuple[str, str, str]:
    return (
        str(cookie["name"]),
        str(cookie["domain"]),
        str(cookie["path"]),
    )


def _merged_cookies(
    initial: list[dict[str, object]],
    observations: list[list[dict[str, object]]],
) -> list[dict[str, object]]:
    merged = {_cookie_key(item): dict(item) for item in initial}
    for values in observations:
        for item in values:
            merged[_cookie_key(item)] = dict(item)
    return normalize_cookies(
        [merged[key] for key in sorted(merged)]
    )


def _request_once(
    *,
    barrier: threading.Barrier,
    method: str,
    url: str,
    body: bytes | None,
    cookies: list[dict[str, object]],
    timeout: float,
    deadline: float,
    budget: _ResponseBudget,
) -> tuple[int, bytes, bool, list[dict[str, object]], int]:
    barrier.wait(timeout=timeout)
    started = time.monotonic_ns()
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ActiveProbeError("probe_deadline_exceeded")
    with requests.Session() as session:
        _load_requests_cookies(session, cookies)
        try:
            with session.request(
                method,
                url,
                data=body,
                allow_redirects=False,
                timeout=(remaining, remaining),
                stream=True,
            ) as response:
                payload, truncated = _read_response(
                    response,
                    maximum=MAX_RESPONSE_BYTES,
                    deadline=deadline,
                    budget=budget,
                )
                status = response.status_code
        except requests.RequestException as error:
            raise ActiveProbeError("probe_transport_failed") from error
        observed = _dump_requests_cookies(session)
    return (
        status,
        payload,
        truncated,
        observed,
        time.monotonic_ns() - started,
    )


def _race(
    args: argparse.Namespace,
    *,
    body: bytes | None,
    cookies_before: list[dict[str, object]],
    deadline: float,
) -> tuple[
    dict[str, object],
    list[dict[str, object]],
    list[tuple[str, bytes]],
]:
    records: list[dict[str, object]] = []
    cookie_observations: list[list[dict[str, object]]] = []
    artifacts: list[tuple[str, bytes]] = []
    total_response_bytes = 0
    response_budget = _ResponseBudget(MAX_TOTAL_RESPONSE_BYTES)
    ordinal = 0
    for attempt in range(1, args.attempts + 1):
        barrier = threading.Barrier(args.concurrency)
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=args.concurrency,
            thread_name_prefix="ctfos-web-race",
        ) as executor:
            futures = [
                executor.submit(
                    _request_once,
                    barrier=barrier,
                    method=args.method,
                    url=args.url,
                    body=body,
                    cookies=cookies_before,
                    timeout=max(0.1, deadline - time.monotonic()),
                    deadline=deadline,
                    budget=response_budget,
                )
                for _index in range(args.concurrency)
            ]
            batch = [future.result() for future in futures]
        for index, value in enumerate(batch, start=1):
            ordinal += 1
            status, payload, truncated, cookies, duration_ns = value
            total_response_bytes += len(payload)
            if total_response_bytes > MAX_TOTAL_RESPONSE_BYTES:
                raise ActiveProbeError(
                    "aggregate_response_size_exceeded"
                )
            name = f"response-{ordinal:04d}.bin"
            artifacts.append((name, payload))
            cookie_observations.append(cookies)
            records.append(
                {
                    "artifact": name,
                    "attempt": attempt,
                    "body_sha256": _sha256(payload),
                    "body_size_bytes": len(payload),
                    "duration_ns": duration_ns,
                    "index": index,
                    "ordinal": ordinal,
                    "status": status,
                    "truncated": truncated,
                }
            )
        batch_digest = _sha256(
            _canonical_bytes(records[-args.concurrency :])
        )
        for record in records[-args.concurrency :]:
            record["batch_sha256"] = batch_digest
    return (
        {
            "attempts": args.attempts,
            "concurrency": args.concurrency,
            "mode": "race",
            "request_count": len(records),
            "responses": records,
        },
        _merged_cookies(cookies_before, cookie_observations),
        artifacts,
    )


class _CallbackServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], token: str) -> None:
        super().__init__(address, _CallbackHandler)
        self.callback_event = threading.Event()
        self.callback_lock = threading.Lock()
        self.callbacks: list[dict[str, object]] = []
        self.callback_bodies: list[bytes] = []
        self.token = token


class _CallbackHandler(BaseHTTPRequestHandler):
    server: _CallbackServer

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _capture(self) -> None:
        length_text = self.headers.get("Content-Length", "0")
        try:
            length = int(length_text, 10)
        except ValueError:
            length = -1
        if not 0 <= length <= MAX_CALLBACK_BYTES:
            self.send_error(413)
            return
        body = self.rfile.read(length)
        path = self.path.encode("utf-8", errors="surrogatepass")
        expected_prefix = f"/{self.server.token}".encode("ascii")
        if not path.startswith(expected_prefix):
            self.send_error(404)
            return
        record = {
            "body_sha256": _sha256(body),
            "body_size_bytes": len(body),
            "header_names_sha256": _sha256(
                _canonical_bytes(
                    sorted(
                        name.casefold()
                        for name in self.headers
                    )
                )
            ),
            "method": self.command,
            "path_sha256": _sha256(path),
        }
        with self.server.callback_lock:
            if len(self.server.callbacks) < MAX_CALLBACKS:
                self.server.callbacks.append(record)
                self.server.callback_bodies.append(body)
            self.server.callback_event.set()
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    do_DELETE = _capture
    do_GET = _capture
    do_HEAD = _capture
    do_OPTIONS = _capture
    do_PATCH = _capture
    do_POST = _capture
    do_PUT = _capture


def _oob(
    args: argparse.Namespace,
    *,
    body: bytes,
    cookies_before: list[dict[str, object]],
    deadline: float,
) -> tuple[
    dict[str, object],
    list[dict[str, object]],
    list[tuple[str, bytes]],
]:
    if body.count(CALLBACK_PLACEHOLDER) != 1:
        raise ActiveProbeError("oob_placeholder_count_invalid")
    server = _CallbackServer(("0.0.0.0", 0), args.callback_token)
    listener = threading.Thread(
        target=server.serve_forever,
        name="ctfos-oob-listener",
        daemon=True,
    )
    listener.start()
    try:
        address = socket.gethostbyname(socket.gethostname())
        if address.startswith("127.") or address in {"0.0.0.0", "::1"}:
            raise ActiveProbeError("oob_callback_address_unavailable")
        callback_url = (
            f"http://{address}:{server.server_port}/"
            f"{args.callback_token}"
        ).encode("ascii")
        rendered = body.replace(CALLBACK_PLACEHOLDER, callback_url)
        barrier = threading.Barrier(1)
        (
            status,
            response_body,
            truncated,
            cookies_after,
            duration_ns,
        ) = _request_once(
            barrier=barrier,
            method=args.method,
            url=args.url,
            body=rendered,
            cookies=cookies_before,
            timeout=max(0.1, deadline - time.monotonic()),
            deadline=deadline,
            budget=_ResponseBudget(MAX_TOTAL_RESPONSE_BYTES),
        )
        remaining = min(
            args.callback_timeout,
            max(0.0, deadline - time.monotonic()),
        )
        server.callback_event.wait(remaining)
    finally:
        server.shutdown()
        server.server_close()
        listener.join(timeout=2)
    artifacts: list[tuple[str, bytes]] = [
        ("trigger-response.bin", response_body)
    ]
    for index, payload in enumerate(
        server.callback_bodies,
        start=1,
    ):
        artifacts.append((f"callback-{index:02d}.bin", payload))
    return (
        {
            "callback_count": len(server.callbacks),
            "callbacks": server.callbacks,
            "mode": "oob",
            "rendered_request_sha256": _sha256(rendered),
            "rendered_request_size_bytes": len(rendered),
            "trigger": {
                "body_sha256": _sha256(response_body),
                "body_size_bytes": len(response_body),
                "duration_ns": duration_ns,
                "status": status,
                "truncated": truncated,
            },
        },
        cookies_after,
        artifacts,
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("oob", "race"))
    parser.add_argument("url", type=_validate_url)
    parser.add_argument(
        "-X",
        "--method",
        choices=("DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"),
        default="POST",
    )
    parser.add_argument("--session", choices=SESSION_NAMES, required=True)
    parser.add_argument("--data-file", type=Path)
    parser.add_argument("--concurrency", type=int, default=2)
    parser.add_argument("--attempts", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--callback-timeout", type=float, default=5.0)
    parser.add_argument("--callback-token", default="")
    args = parser.parse_args()
    if (
        not 2 <= args.concurrency <= MAX_CONCURRENCY
        or not 1 <= args.attempts <= MAX_ATTEMPTS
        or args.concurrency * args.attempts > MAX_REQUESTS
        or not 1 <= args.timeout <= 300
        or not 0.1 <= args.callback_timeout <= 30
    ):
        parser.error("active probe bounds are invalid")
    if args.data_file is not None and not args.data_file.is_file():
        parser.error("--data-file must name one regular file")
    if args.mode == "oob":
        if (
            args.data_file is None
            or len(args.callback_token) != 32
            or any(
                character not in "0123456789abcdef"
                for character in args.callback_token
            )
        ):
            parser.error("OOB mode requires data file and 32-hex token")
        args.concurrency = 1
        args.attempts = 1
    elif args.callback_token:
        parser.error("race mode rejects an OOB callback token")
    return args


def main() -> int:
    args = _parse_args()
    output_descriptor = open_output_dir(OUTPUT_DIR)
    body = (
        None
        if args.data_file is None
        else _read_bounded(args.data_file, MAX_BODY_BYTES)
    )
    private_session_root, private_timeline_root = engine_private_roots()
    started = time.monotonic()
    started_ns = time.monotonic_ns()
    deadline = started + args.timeout
    try:
        with PersistentWebSession(
            private_session_root,
            private_timeline_root,
            OUTPUT_DIR,
            args.session,
        ) as session:
            cookies_before = session.load_cookies()
            if args.mode == "race":
                report, cookies_after, artifacts = _race(
                    args,
                    body=body,
                    cookies_before=cookies_before,
                    deadline=deadline,
                )
            else:
                assert body is not None
                report, cookies_after, artifacts = _oob(
                    args,
                    body=body,
                    cookies_before=cookies_before,
                    deadline=deadline,
                )
            cookies_after = session.save_cookies(cookies_after)
            for name, payload in artifacts:
                atomic_write(
                    output_descriptor,
                    name,
                    redact_cookie_bytes(
                        payload,
                        cookies_before,
                        cookies_after,
                    ),
                )
            event = session.record_exchange(
                source="http",
                method=args.method,
                url=args.url,
                status=(
                    report["trigger"]["status"]
                    if args.mode == "oob"
                    else report["responses"][-1]["status"]
                ),
                cookies_before=cookies_before,
                cookies_after=cookies_after,
                request_headers={},
                response_headers={},
                artifact=str(OUTPUT_DIR / "report.json"),
            )
            report = {
                **report,
                "artifact_names": [name for name, _payload in artifacts],
                "cookie_transition_sha256": _sha256(
                    _canonical_bytes(event["cookie_transition"])
                ),
                "elapsed_ns": time.monotonic_ns() - started_ns,
                "protocol": PROTOCOL,
                "schema_version": 1,
                "session": args.session,
                "timeline_ordinal": event["ordinal"],
            }
            report_payload = _canonical_bytes(report)
            report_payload = redact_cookie_bytes(
                report_payload,
                cookies_before,
                cookies_after,
            )
            atomic_write(
                output_descriptor,
                "report.json",
                report_payload,
            )
    except (
        ActiveProbeError,
        OSError,
        requests.RequestException,
        WebSessionStateError,
    ) as error:
        failure = _canonical_bytes(
            {
                "error": type(error).__name__,
                "ok": False,
                "protocol": PROTOCOL,
                "schema_version": 1,
            }
        )
        atomic_write(output_descriptor, "error.json", failure)
        print(failure.decode("ascii").strip())
        return 2
    print(report_payload.decode("ascii").strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
