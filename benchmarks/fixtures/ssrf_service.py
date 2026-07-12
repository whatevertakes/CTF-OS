#!/usr/bin/env python3
"""Docker-only SSRF fixture; this file is never mounted into solver workspaces."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import socket
import socketserver
from threading import Thread
from urllib.parse import parse_qs, urlparse
from urllib.request import urlopen

FLAG = os.environ["BENCH_FLAG"]
NONCE = os.environ["BENCH_NONCE"]
INTERNAL_PORT = int(os.environ.get("BENCH_INTERNAL_PORT", "19080"))
meta_available = True


class Internal(BaseHTTPRequestHandler):
    def do_GET(self):
        global meta_available
        if self.path == "/meta" and meta_available:
            meta_available = False
            body = json.dumps({"kind": "internal_endpoint", "endpoint": f"/admin/{NONCE}"}).encode()
            self.send_response(200)
        elif self.path == f"/admin/{NONCE}":
            body = FLAG.encode()
            self.send_response(200)
        else:
            body = b"not found"
            self.send_response(404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


class Origin(BaseHTTPRequestHandler):
    def _fetch(self, target):
        requested = urlparse(target)
        if requested.scheme != "http" or requested.hostname != "internal.local":
            return b"blocked by challenge allowlist", 403
        try:
            with urlopen(f"http://127.0.0.1:{INTERNAL_PORT}{requested.path}", timeout=2) as response:
                return response.read(), response.status
        except Exception as exc:
            return str(exc).encode(), 502

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            body, status = b"use /fetch?url=http://internal.local/meta", 200
        elif parsed.path == "/fetch":
            target = parse_qs(parsed.query).get("url", [""])[0]
            body, status = self._fetch(target)
        else:
            body, status = b"not found", 404
        self._reply(body, status)

    def do_POST(self):
        if urlparse(self.path).path != "/fetch":
            self._reply(b"not found", 404)
            return
        try:
            length = min(int(self.headers.get("Content-Length", "0")), 4096)
            target = str(json.loads(self.rfile.read(length)).get("url", ""))
        except (ValueError, json.JSONDecodeError):
            self._reply(b"invalid JSON", 400)
            return
        body, status = self._fetch(target)
        self._reply(body, status)

    def _reply(self, body, status):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


class UnixHTTPServer(socketserver.UnixStreamServer):
    allow_reuse_address = True


if __name__ == "__main__":
    internal = HTTPServer(("127.0.0.1", INTERNAL_PORT), Internal)
    Thread(target=internal.serve_forever, daemon=True).start()
    path = "/shared/origin.sock"
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    origin = UnixHTTPServer(path, Origin)
    os.chmod(path, 0o777)
    origin.serve_forever()
