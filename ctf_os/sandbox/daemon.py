"""Capability-authenticated Unix-socket facade for challenge sandboxes."""

from __future__ import annotations

import base64
import builtins
import hashlib
import hmac
import json
import os
import secrets
import socketserver
import stat
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .client import (
    MAX_RPC_BYTES,
    ChallengeSandboxClient,
    command_from_dict,
    ref_from_dict,
)
from .types import (
    ProofInput,
    SandboxError,
    ScopeError,
    validate_deadline_monotonic_seconds,
)


class CapabilityError(SandboxError):
    """A capability is invalid, expired, or not registered."""


def _retry_secret_unlink(path: Path) -> BaseException | None:
    """Remove one exact incomplete secret after one transient failure."""

    first_error: BaseException | None = None
    for attempt in range(2):
        try:
            path.unlink(missing_ok=True)
        except BaseException as error:
            if first_error is None:
                first_error = error
            else:
                first_error.add_note(
                    f"capability secret unlink retry failed: {error}"
                )
            if attempt == 0:
                continue
        else:
            if first_error is not None and not isinstance(
                first_error, Exception
            ):
                return first_error
            return None
    return first_error


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.b64decode(
            value + padding,
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, base64.binascii.Error) as error:
        raise CapabilityError("invalid sandbox capability encoding") from error


class CapabilityAuthority:
    """Issue short opaque signed capabilities bound to a scope fingerprint."""

    def __init__(self, secret: bytes) -> None:
        if len(secret) < 32:
            raise ValueError("capability secret must be at least 32 bytes")
        self._secret = bytes(secret)

    @classmethod
    def from_file(cls, path: Path) -> CapabilityAuthority:
        """Load or safely create a mode-0600 daemon secret."""

        secret_path = path.expanduser().resolve()
        secret_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(secret_path, flags)
        except FileNotFoundError:
            stream = None
            remove_incomplete = True
            creation_complete = False
            primary_error: BaseException | None = None

            def private_opener(
                candidate: str,
                requested_flags: int,
            ) -> int:
                """Create the secret privately before any descriptor handoff."""

                private_flags = requested_flags | os.O_CLOEXEC
                private_flags |= getattr(os, "O_NOFOLLOW", 0)
                return os.open(candidate, private_flags, 0o600)

            try:
                try:
                    # ``xb`` preserves O_EXCL semantics while returning an
                    # owning object. If an interrupt lands before the caller
                    # stores it, object finalization closes the exact fd and
                    # the outer cleanup below removes the known path.
                    stream = builtins.open(
                        secret_path,
                        "xb",
                        buffering=0,
                        opener=private_opener,
                    )
                except FileExistsError:
                    remove_incomplete = False
                    raise
                except Exception:
                    # An ordinary failed open did not transfer ownership.
                    remove_incomplete = False
                    raise
                os.fchmod(stream.fileno(), 0o600)
                remaining = memoryview(secrets.token_bytes(32))
                while remaining:
                    written = stream.write(remaining)
                    if written is None or written <= 0:
                        raise OSError(
                            "capability secret write made no progress"
                        )
                    remaining = remaining[written:]
                os.fsync(stream.fileno())
                creation_complete = True
            except BaseException as error:
                primary_error = error
                raise
            finally:
                cleanup_errors: list[BaseException] = []
                if stream is not None:
                    try:
                        stream.close()
                    except BaseException as error:
                        cleanup_errors.append(error)
                if remove_incomplete and not creation_complete:
                    unlink_error = _retry_secret_unlink(secret_path)
                    if unlink_error is not None:
                        cleanup_errors.append(unlink_error)
                if cleanup_errors:
                    if primary_error is not None:
                        for cleanup_error in cleanup_errors:
                            primary_error.add_note(
                                "capability secret cleanup failed: "
                                f"{cleanup_error}"
                            )
                    else:
                        cleanup_error = cleanup_errors[0]
                        for additional_error in cleanup_errors[1:]:
                            cleanup_error.add_note(
                                "additional capability secret cleanup "
                                f"failure: {additional_error}"
                            )
                        raise cleanup_error
            descriptor = os.open(secret_path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_size < 32
                or opened.st_size > 4096
                or opened.st_mode & 0o077
            ):
                raise CapabilityError(
                    "capability secret must be a private regular file"
                )
            chunks: list[bytes] = []
            remaining = 4097
            while remaining:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            after = os.fstat(descriptor)
            secret = b"".join(chunks)
            stable_fields = (
                "st_dev",
                "st_ino",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            )
            if (
                len(secret) != opened.st_size
                or len(secret) > 4096
                or any(
                    getattr(after, field) != getattr(opened, field)
                    for field in stable_fields
                )
            ):
                raise CapabilityError(
                    "capability secret changed while being read"
                )
        finally:
            os.close(descriptor)
        return cls(secret)

    def issue(self, scope_fingerprint: str, *, ttl_seconds: int = 8 * 60 * 60) -> str:
        if (
            not isinstance(scope_fingerprint, str)
            or len(scope_fingerprint) != 64
            or any(character not in "0123456789abcdef" for character in scope_fingerprint)
        ):
            raise ValueError("invalid scope fingerprint")
        if not 1 <= ttl_seconds <= 7 * 24 * 60 * 60:
            raise ValueError("ttl_seconds must be between 1 second and 7 days")
        payload = json.dumps(
            {
                "v": 1,
                "scope": scope_fingerprint,
                "exp": int(time.time()) + ttl_seconds,
                "nonce": secrets.token_hex(16),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        encoded = _b64encode(payload)
        signature = _b64encode(
            hmac.new(self._secret, encoded.encode("ascii"), hashlib.sha256).digest()
        )
        return f"{encoded}.{signature}"

    def verify(self, token: str) -> str:
        if not isinstance(token, str) or len(token) > 8192 or token.count(".") != 1:
            raise CapabilityError("invalid sandbox capability")
        encoded, signature = token.split(".", 1)
        expected = hmac.new(
            self._secret,
            encoded.encode("ascii", errors="strict"),
            hashlib.sha256,
        ).digest()
        provided = _b64decode(signature)
        if not hmac.compare_digest(expected, provided):
            raise CapabilityError("invalid sandbox capability signature")
        try:
            payload = json.loads(_b64decode(encoded).decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise CapabilityError("invalid sandbox capability payload") from error
        if not isinstance(payload, dict) or payload.get("v") != 1:
            raise CapabilityError("unsupported sandbox capability")
        try:
            expires = int(payload["exp"])
            scope = str(payload["scope"])
        except (KeyError, TypeError, ValueError) as error:
            raise CapabilityError("invalid sandbox capability payload") from error
        if expires < int(time.time()):
            raise CapabilityError("sandbox capability expired")
        if (
            len(scope) != 64
            or any(character not in "0123456789abcdef" for character in scope)
        ):
            raise CapabilityError("invalid sandbox capability scope")
        return scope


def _status_dict(status: object) -> dict[str, Any]:
    value = asdict(status)
    value.pop("ref", None)
    state = value.get("status")
    if hasattr(state, "value"):
        value["status"] = state.value
    return value


class SandboxService:
    """Dispatch a narrow operation set after capability and scope checks."""

    def __init__(self, authority: CapabilityAuthority) -> None:
        self.authority = authority
        self._clients: dict[str, ChallengeSandboxClient] = {}

    def register(self, client: ChallengeSandboxClient) -> None:
        fingerprint = client.scope_fingerprint
        existing = self._clients.get(fingerprint)
        if existing is not None and existing is not client:
            raise ScopeError("scope fingerprint is already registered")
        self._clients[fingerprint] = client

    def unregister(self, scope_fingerprint: str) -> None:
        self._clients.pop(scope_fingerprint, None)

    def issue(self, scope_fingerprint: str, *, ttl_seconds: int = 8 * 60 * 60) -> str:
        if scope_fingerprint not in self._clients:
            raise ScopeError("cannot issue a capability for an unknown scope")
        return self.authority.issue(scope_fingerprint, ttl_seconds=ttl_seconds)

    def dispatch(self, request: object) -> Any:
        if not isinstance(request, dict) or request.get("schema_version") != 1:
            raise SandboxError("unsupported sandbox request")
        scope = self.authority.verify(request.get("token"))
        try:
            client = self._clients[scope]
        except KeyError as error:
            raise CapabilityError("sandbox capability scope is not registered") from error
        operation = request.get("operation")
        params = request.get("params", {})
        if not isinstance(operation, str) or not isinstance(params, dict):
            raise SandboxError("invalid sandbox request")

        if operation == "initialize_workspace":
            client.initialize_workspace(
                deadline_monotonic_seconds=(
                    validate_deadline_monotonic_seconds(
                        params.get("deadline_monotonic_seconds")
                    )
                )
            )
            return {"initialized": True}
        if operation == "run":
            return asdict(client.run(command_from_dict(params.get("command"))))
        if operation == "start_job":
            raise SandboxError(
                "background job start is disabled until a lease supervisor exists"
            )

        if operation in {"job_status", "job_log", "cancel_job"}:
            ref = ref_from_dict(params.get("ref"))
            if ref.scope_fingerprint != scope:
                raise ScopeError("job reference belongs to another challenge")
            if operation == "job_status":
                return _status_dict(client.job_status(ref))
            if operation == "job_log":
                value = asdict(
                    client.job_log(
                        ref,
                        tail_bytes=params.get("tail_bytes", 8192),
                    )
                )
                value.pop("ref", None)
                return value
            return _status_dict(
                client.cancel_job(
                    ref,
                    grace_seconds=params.get("grace_seconds", 3),
                )
            )

        if operation == "register_artifact":
            return asdict(
                client.register_artifact(
                    params.get("locator"),
                    maximum_bytes=params.get(
                        "maximum_bytes",
                        16 * 1024 * 1024 * 1024,
                    ),
                )
            )
        if operation == "run_clean_proof":
            inputs = params.get("input_locators", [])
            if not isinstance(inputs, list) or not all(
                isinstance(item, str) for item in inputs
            ):
                raise ValueError("input_locators must be an array of strings")
            proof_input_values = params.get("proof_inputs", [])
            if not isinstance(proof_input_values, list) or not all(
                isinstance(item, dict) for item in proof_input_values
            ):
                raise ValueError("proof_inputs must be an array of objects")
            proof_inputs = tuple(
                ProofInput.from_mapping(item) for item in proof_input_values
            )
            return asdict(
                client.run_clean_proof(
                    command_from_dict(params.get("command")),
                    input_locators=inputs,
                    proof_inputs=proof_inputs,
                )
            )
        raise SandboxError(f"unsupported sandbox operation: {operation!r}")

    def handle_bytes(self, data: bytes) -> bytes:
        if len(data) > MAX_RPC_BYTES:
            response = self._error("request_too_large", "request exceeds 1 MiB")
        else:
            try:
                request = json.loads(data.decode("utf-8"))
                response = {
                    "schema_version": 1,
                    "ok": True,
                    "result": self.dispatch(request),
                }
            except (
                CapabilityError,
                SandboxError,
                ValueError,
                TypeError,
                KeyError,
            ) as error:
                response = self._error(
                    error.__class__.__name__,
                    str(error) or "sandbox operation failed",
                )
            except (UnicodeError, json.JSONDecodeError):
                response = self._error("invalid_json", "request is not valid JSON")
        encoded = (
            json.dumps(
                response,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        if len(encoded) > MAX_RPC_BYTES:
            encoded = (
                json.dumps(
                    self._error(
                        "response_too_large",
                        "response exceeds 1 MiB",
                    ),
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
        return encoded

    @staticmethod
    def _error(code: str, message: str) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "ok": False,
            "error": {
                "code": code,
                "message": message[:4096],
            },
        }


class _SandboxRequestHandler(socketserver.StreamRequestHandler):
    def _write_response(self, response: bytes) -> None:
        try:
            self.wfile.write(response)
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            # The backend operation and exact cleanup are authoritative even if
            # a caller exceeds its bounded response grace and disconnects.
            return

    def handle(self) -> None:
        data = self.rfile.readline(MAX_RPC_BYTES + 1)
        if len(data) > MAX_RPC_BYTES or not data.endswith(b"\n"):
            self._write_response(
                self.server.service.handle_bytes(b" " * (MAX_RPC_BYTES + 1))
            )
            return
        self._write_response(self.server.service.handle_bytes(data))


class UnixSandboxServer(socketserver.ThreadingUnixStreamServer):
    """Small threaded server.  The filesystem mode and token are both required."""

    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, socket_path: Path, service: SandboxService) -> None:
        resolved = socket_path.expanduser().resolve()
        resolved.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if resolved.exists() or resolved.is_symlink():
            current = resolved.stat(follow_symlinks=False)
            kind = "socket" if stat.S_ISSOCK(current.st_mode) else "non-socket"
            raise SandboxError(
                f"refusing existing {kind} daemon path: {resolved}"
            )
        self.service = service
        self.socket_path = resolved
        super().__init__(str(resolved), _SandboxRequestHandler)
        os.chmod(resolved, 0o600)

    def server_close(self) -> None:
        super().server_close()
        try:
            current = self.socket_path.stat(follow_symlinks=False)
        except FileNotFoundError:
            return
        if stat.S_ISSOCK(current.st_mode):
            self.socket_path.unlink()
