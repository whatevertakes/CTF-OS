from __future__ import annotations

import contextlib
import fcntl
import hashlib
import importlib.util
import io
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
from urllib.parse import urlsplit

from ctf_os.sandbox.web_private import (
    WebPrivateStateError,
    prepare_web_session_command,
    redact_public_artifacts,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
WEB_TEMPLATE_ROOT = REPOSITORY_ROOT / "ctf-os-image" / "templates" / "web"


def _load_active_probe() -> object:
    """Load the image helper without polluting shared support-module names."""

    support_names = ("safe_output", "session_state")
    previous = {
        name: sys.modules.get(name)
        for name in support_names
    }
    sys.path.insert(0, str(WEB_TEMPLATE_ROOT))
    try:
        for name in support_names:
            sys.modules.pop(name, None)
        spec = importlib.util.spec_from_file_location(
            "ctfos_web_active_probe_transport_under_test",
            WEB_TEMPLATE_ROOT / "active_probe.py",
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(WEB_TEMPLATE_ROOT))
        for name in support_names:
            sys.modules.pop(name, None)
            if previous[name] is not None:
                sys.modules[name] = previous[name]


ACTIVE_PROBE = _load_active_probe()


def _non_loopback_ipv4() -> str | None:
    """Return a local interface address without making a network request."""

    query = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for _index, name in socket.if_nameindex():
            try:
                result = fcntl.ioctl(
                    query.fileno(),
                    0x8915,
                    struct.pack("256s", name.encode("ascii")[:15]),
                )
            except OSError:
                continue
            address = socket.inet_ntoa(result[20:24])
            if not address.startswith("127."):
                return address
    finally:
        query.close()
    return None


@contextlib.contextmanager
def _serve(
    handler: type[BaseHTTPRequestHandler],
) -> object:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    thread = threading.Thread(
        target=server.serve_forever,
        name="ctfos-web-active-probe-test-server",
        daemon=True,
    )
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class _SilentHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_arguments: object) -> None:
        return


class _ConcurrentRaceHandler(_SilentHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        server = self.server
        condition = server.arrival_condition  # type: ignore[attr-defined]
        with condition:
            server.inflight += 1  # type: ignore[attr-defined]
            server.request_count += 1  # type: ignore[attr-defined]
            batch = (  # type: ignore[attr-defined]
                server.request_count - 1  # type: ignore[attr-defined]
            ) // server.expected_concurrency  # type: ignore[attr-defined]
            server.batch_arrivals[batch] = (  # type: ignore[attr-defined]
                server.batch_arrivals.get(batch, 0) + 1  # type: ignore[attr-defined]
            )
            server.max_inflight = max(  # type: ignore[attr-defined]
                server.max_inflight,  # type: ignore[attr-defined]
                server.inflight,  # type: ignore[attr-defined]
            )
            if (
                server.batch_arrivals[batch]  # type: ignore[attr-defined]
                == server.expected_concurrency  # type: ignore[attr-defined]
            ):
                server.released_batches.add(batch)  # type: ignore[attr-defined]
                condition.notify_all()
            else:
                released = condition.wait_for(
                    lambda: (
                        batch  # type: ignore[attr-defined]
                        in server.released_batches
                    ),
                    timeout=2,
                )
                if not released:
                    server.serialized = True  # type: ignore[attr-defined]
            reflected_cookie = self.headers.get("Cookie", "")

        payload = (
            f"cookie={reflected_cookie}; rotated=rotated-cookie-secret"
        ).encode("ascii")
        self.send_response(200)
        self.send_header(
            "Set-Cookie",
            "rotated=rotated-cookie-secret; Path=/; HttpOnly",
        )
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
        self.wfile.flush()
        with condition:
            server.inflight -= 1  # type: ignore[attr-defined]


class _OobTriggerHandler(_SilentHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        prefix = b"callback="
        if not body.startswith(prefix):
            self.send_error(400)
            return
        callback = body[len(prefix) :].decode("ascii")
        parsed = urlsplit(callback)
        connection = HTTPConnection(
            parsed.hostname,
            parsed.port,
            timeout=3,
        )
        callback_body = b"synthetic-oob-proof"
        connection.request(
            "POST",
            parsed.path,
            body=callback_body,
            headers={"Content-Type": "application/octet-stream"},
        )
        response = connection.getresponse()
        response.read()
        connection.close()
        self.server.callback_status = response.status  # type: ignore[attr-defined]
        payload = b"trigger-accepted"
        self.send_response(202)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class _LargeResponseHandler(_SilentHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        payload = b"target-controlled-error-text-" + (b"x" * 128)
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def _cookie(
    name: str,
    value: str,
    *,
    domain: str = "127.0.0.1",
) -> dict[str, object]:
    return {
        "domain": domain,
        "expires": None,
        "http_only": True,
        "name": name,
        "path": "/",
        "same_site": "Lax",
        "secure": False,
        "value": value,
    }


class WebActiveProbeTransportTests(unittest.TestCase):
    def test_main_runs_true_concurrent_race_and_never_publishes_cookies(
        self,
    ) -> None:
        initial_secret = "initial-cookie-secret"
        with tempfile.TemporaryDirectory(
            prefix="ctfos-web-active-race-"
        ) as temporary:
            root = Path(temporary)
            work = root / "work"
            private_session = root / "private-session"
            private_timeline = root / "private-timeline"
            output = work / "web-active"
            work.mkdir()
            private_session.mkdir()
            private_timeline.mkdir()
            cookie_path = private_session / "cookies.json"
            cookie_path.write_text(
                json.dumps(
                    {
                        "cookies": [
                            _cookie("sessionid", initial_secret)
                        ],
                        "schema_version": 1,
                        "session": "attacker",
                    },
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n",
                encoding="ascii",
            )
            os.chmod(cookie_path, 0o600)

            with _serve(_ConcurrentRaceHandler) as server:
                server.arrival_condition = threading.Condition()
                server.expected_concurrency = 4
                server.inflight = 0
                server.max_inflight = 0
                server.request_count = 0
                server.serialized = False
                server.batch_arrivals = {}
                server.released_batches = set()
                url = (
                    f"http://127.0.0.1:{server.server_port}/claim"
                )
                argv = [
                    "active_probe.py",
                    "race",
                    url,
                    "--session",
                    "attacker",
                    "--concurrency",
                    "4",
                    "--attempts",
                    "2",
                    "--timeout",
                    "8",
                ]
                stdout = io.StringIO()
                stderr = io.StringIO()
                previous_output = ACTIVE_PROBE.OUTPUT_DIR
                try:
                    ACTIVE_PROBE.OUTPUT_DIR = output
                    with (
                        mock.patch.object(sys, "argv", argv),
                        mock.patch.object(
                            ACTIVE_PROBE,
                            "engine_private_roots",
                            return_value=(
                                private_session,
                                private_timeline,
                            ),
                        ),
                        contextlib.redirect_stdout(stdout),
                        contextlib.redirect_stderr(stderr),
                    ):
                        result = ACTIVE_PROBE.main()
                finally:
                    ACTIVE_PROBE.OUTPUT_DIR = previous_output

            self.assertEqual(result, 0, stderr.getvalue())
            self.assertFalse(server.serialized)
            self.assertGreaterEqual(server.max_inflight, 4)
            self.assertEqual(server.request_count, 8)
            self.assertEqual(server.batch_arrivals, {0: 4, 1: 4})
            report = json.loads((output / "report.json").read_bytes())
            self.assertEqual(report["request_count"], 8)
            self.assertEqual(report["concurrency"], 4)
            self.assertEqual(report["attempts"], 2)
            self.assertEqual(
                report["artifact_names"],
                [
                    f"response-{index:04d}.bin"
                    for index in range(1, 9)
                ],
            )
            public_bytes = b"\n".join(
                path.read_bytes()
                for path in sorted(output.iterdir())
            ) + stdout.getvalue().encode("utf-8")
            self.assertNotIn(initial_secret.encode(), public_bytes)
            self.assertNotIn(b"rotated-cookie-secret", public_bytes)
            self.assertIn(
                b"*" * len(initial_secret),
                (output / "response-0001.bin").read_bytes(),
            )
            private_jar = cookie_path.read_bytes()
            self.assertIn(b"rotated-cookie-secret", private_jar)

    def test_oob_listener_captures_exact_callback_body(self) -> None:
        callback_address = _non_loopback_ipv4()
        if callback_address is None:
            self.skipTest("no callback-capable private IPv4 interface")
        with _serve(_OobTriggerHandler) as server:
            server.callback_status = None
            token = "a" * 32
            args = SimpleNamespace(
                callback_timeout=3.0,
                callback_token=token,
                method="POST",
                url=f"http://127.0.0.1:{server.server_port}/trigger",
            )
            with mock.patch.object(
                ACTIVE_PROBE.socket,
                "gethostbyname",
                return_value=callback_address,
            ):
                report, cookies, artifacts = ACTIVE_PROBE._oob(
                    args,
                    body=b"callback={{CTF_OOB_URL}}",
                    cookies_before=[],
                    deadline=time.monotonic() + 6,
                )
        callback_body = b"synthetic-oob-proof"
        self.assertEqual(server.callback_status, 204)
        self.assertEqual(cookies, [])
        self.assertEqual(report["callback_count"], 1)
        self.assertEqual(report["callbacks"][0]["method"], "POST")
        self.assertEqual(
            report["callbacks"][0]["body_sha256"],
            hashlib.sha256(callback_body).hexdigest(),
        )
        self.assertEqual(
            report["callbacks"][0]["body_size_bytes"],
            len(callback_body),
        )
        self.assertEqual(
            artifacts,
            [
                ("trigger-response.bin", b"trigger-accepted"),
                ("callback-01.bin", callback_body),
            ],
        )

    def test_helper_rejects_argument_bounds_and_unsafe_inputs(self) -> None:
        invalid_argv = (
            ("race", "http://127.0.0.1/", "--session", "attacker",
             "--concurrency", "1"),
            ("race", "http://127.0.0.1/", "--session", "attacker",
             "--concurrency", "33"),
            ("race", "http://127.0.0.1/", "--session", "attacker",
             "--attempts", "17"),
            ("race", "http://127.0.0.1/", "--session", "attacker",
             "--concurrency", "32", "--attempts", "9"),
            ("oob", "http://127.0.0.1/", "--session", "attacker",
             "--callback-token", "not-hex"),
        )
        for arguments in invalid_argv:
            with self.subTest(arguments=arguments):
                with (
                    mock.patch.object(
                        sys,
                        "argv",
                        ["active_probe.py", *arguments],
                    ),
                    contextlib.redirect_stderr(io.StringIO()),
                    self.assertRaises(SystemExit) as raised,
                ):
                    ACTIVE_PROBE._parse_args()
                self.assertEqual(raised.exception.code, 2)

        with tempfile.TemporaryDirectory(
            prefix="ctfos-web-active-input-"
        ) as temporary:
            root = Path(temporary)
            oversized = root / "oversized.bin"
            oversized.write_bytes(b"x" * 17)
            with self.assertRaises(ACTIVE_PROBE.ActiveProbeError):
                ACTIVE_PROBE._read_bounded(oversized, 16)
            symlink = root / "body.bin"
            symlink.symlink_to(oversized)
            with self.assertRaises(OSError):
                ACTIVE_PROBE._read_bounded(symlink, 32)
        with self.assertRaises(ACTIVE_PROBE.ActiveProbeError):
            ACTIVE_PROBE._oob(
                SimpleNamespace(),
                body=b"{{CTF_OOB_URL}}{{CTF_OOB_URL}}",
                cookies_before=[],
                deadline=time.monotonic() + 1,
            )

    def test_aggregate_budget_is_shared_and_failure_publishes_no_body(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="ctfos-web-active-budget-"
        ) as temporary:
            root = Path(temporary)
            work = root / "work"
            output = work / "web-active"
            private_session = root / "private-session"
            private_timeline = root / "private-timeline"
            work.mkdir()
            private_session.mkdir()
            private_timeline.mkdir()
            with _serve(_LargeResponseHandler) as server:
                argv = [
                    "active_probe.py",
                    "race",
                    f"http://127.0.0.1:{server.server_port}/large",
                    "--session",
                    "attacker",
                    "--concurrency",
                    "2",
                    "--attempts",
                    "1",
                    "--timeout",
                    "5",
                ]
                stdout = io.StringIO()
                previous_output = ACTIVE_PROBE.OUTPUT_DIR
                try:
                    ACTIVE_PROBE.OUTPUT_DIR = output
                    with (
                        mock.patch.object(sys, "argv", argv),
                        mock.patch.object(
                            ACTIVE_PROBE,
                            "engine_private_roots",
                            return_value=(
                                private_session,
                                private_timeline,
                            ),
                        ),
                        mock.patch.object(
                            ACTIVE_PROBE,
                            "MAX_RESPONSE_BYTES",
                            256,
                        ),
                        mock.patch.object(
                            ACTIVE_PROBE,
                            "MAX_TOTAL_RESPONSE_BYTES",
                            192,
                        ),
                        contextlib.redirect_stdout(stdout),
                        contextlib.redirect_stderr(io.StringIO()),
                    ):
                        result = ACTIVE_PROBE.main()
                finally:
                    ACTIVE_PROBE.OUTPUT_DIR = previous_output

            self.assertEqual(result, 2)
            self.assertEqual(
                sorted(path.name for path in output.iterdir()),
                ["error.json"],
            )
            failure = json.loads((output / "error.json").read_bytes())
            self.assertEqual(failure["error"], "ActiveProbeError")
            self.assertNotIn(
                "target-controlled-error-text",
                stdout.getvalue(),
            )
            self.assertNotIn(
                b"target-controlled-error-text",
                (output / "error.json").read_bytes(),
            )


class WebActiveProbePrivateBoundaryTests(unittest.TestCase):
    def test_only_exact_active_helper_gets_role_mount(self) -> None:
        prepared = prepare_web_session_command(
            category="web",
            argv=(
                "ctf-web-probe",
                "race",
                "http://target.test/claim",
                "--session",
                "attacker",
                "--data-file",
                "/work/request.bin",
            ),
            environment={},
        )
        assert prepared is not None
        self.assertEqual(prepared.kind, "active")
        self.assertEqual(
            prepared.argv[:2],
            (
                "/opt/venvs/main/bin/python",
                "/opt/ctf-templates/web/active_probe.py",
            ),
        )
        for unsafe in (
            "/work/../run/ctfos-web-session/cookies.json",
            "/run/ctfos-web-session/cookies.json",
            "/tmp/request.bin",
        ):
            with self.subTest(unsafe=unsafe):
                with self.assertRaises(WebPrivateStateError):
                    prepare_web_session_command(
                        category="web",
                        argv=(
                            "ctf-web-probe",
                            "race",
                            "http://target.test/claim",
                            "--session",
                            "attacker",
                            "--data-file",
                            unsafe,
                        ),
                        environment={},
                    )
        self.assertIsNone(
            prepare_web_session_command(
                category="web",
                argv=(
                    "python3",
                    "/opt/ctf-templates/web/active_probe.py",
                    "race",
                    "http://target.test/",
                    "--session",
                    "admin",
                ),
                environment={},
            )
        )

    def test_active_artifact_redaction_and_file_count_are_fail_closed(
        self,
    ) -> None:
        secret = "private-cookie-value"
        with tempfile.TemporaryDirectory(
            prefix="ctfos-web-active-public-"
        ) as temporary:
            work = Path(temporary)
            active = work / "web-active"
            active.mkdir()
            (active / "report.json").write_text(secret, encoding="utf-8")
            (active / "response-0001.bin").write_bytes(
                b"prefix " + secret.encode() + b" suffix"
            )
            redact_public_artifacts(
                work,
                previous_run_ids=frozenset(),
                secrets=(secret,),
            )
            self.assertNotIn(
                secret.encode(),
                (active / "report.json").read_bytes(),
            )
            self.assertNotIn(
                secret.encode(),
                (active / "response-0001.bin").read_bytes(),
            )
            (active / "escape.bin").write_bytes(b"x")
            with self.assertRaises(WebPrivateStateError):
                redact_public_artifacts(
                    work,
                    previous_run_ids=frozenset(),
                    secrets=(),
                )
            (active / "escape.bin").unlink()
            outside = work / "outside.json"
            outside.write_text("outside", encoding="utf-8")
            (active / "report.json").unlink()
            (active / "report.json").symlink_to(outside)
            with self.assertRaises(WebPrivateStateError):
                redact_public_artifacts(
                    work,
                    previous_run_ids=frozenset(),
                    secrets=(),
                )

        with tempfile.TemporaryDirectory(
            prefix="ctfos-web-active-count-"
        ) as temporary:
            work = Path(temporary)
            active = work / "web-active"
            active.mkdir()
            for index in range(1, 302):
                (active / f"response-{index:04d}.bin").touch()
            with self.assertRaises(WebPrivateStateError):
                redact_public_artifacts(
                    work,
                    previous_run_ids=frozenset(),
                    secrets=(),
                )


if __name__ == "__main__":
    unittest.main()
