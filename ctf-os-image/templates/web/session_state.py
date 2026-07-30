"""Challenge-scoped Web session state and redacted execution timeline.

Cookie values are kept in a private per-role jar.  The shared timeline records
only cookie names and transition types, never credential or token values.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import secrets
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Mapping, Sequence
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from safe_output import open_output_dir


SCHEMA_VERSION = 1
SESSION_NAMES = ("attacker", "user", "admin")
COOKIE_FILE = "cookies.json"
TIMELINE_FILE = "timeline.json"
LOCK_FILE = ".lock"
MAX_COOKIE_COUNT = 256
MAX_COOKIE_FILE_BYTES = 1024 * 1024
MAX_TIMELINE_EVENTS = 512
MAX_TIMELINE_BYTES = 2 * 1024 * 1024
MAX_COOKIE_NAME_BYTES = 256
MAX_COOKIE_VALUE_BYTES = 16 * 1024
MAX_COOKIE_DOMAIN_BYTES = 1024
MAX_COOKIE_PATH_BYTES = 2048
MAX_URL_BYTES = 8192
MAX_HEADER_COUNT = 200

_COOKIE_NAME = re.compile(r"^[^\x00-\x20\x7f()<>@,;:\\\"/\[\]?={}]+$")
_SECURITY_HEADER_KINDS = {
    "authorization": "authorization",
    "cookie": "cookie",
    "proxy-authorization": "authorization",
    "set-cookie": "cookie",
    "x-auth-token": "authorization",
    "x-csrf-token": "csrf",
    "x-xsrf-token": "csrf",
}


class WebSessionStateError(ValueError):
    """A persisted Web session artifact violates the bounded schema."""


def validate_session_name(value: str) -> str:
    if value not in SESSION_NAMES:
        raise WebSessionStateError(
            "session must be one of: " + ", ".join(SESSION_NAMES)
        )
    return value


def _bounded_text(
    value: object,
    maximum_bytes: int,
    *,
    field: str,
    allow_empty: bool = True,
) -> str:
    if not isinstance(value, str):
        raise WebSessionStateError(f"{field} must be a string")
    if not allow_empty and not value:
        raise WebSessionStateError(f"{field} cannot be empty")
    encoded = value.encode("utf-8")
    if len(encoded) > maximum_bytes:
        raise WebSessionStateError(
            f"{field} exceeds {maximum_bytes} bytes"
        )
    if "\x00" in value:
        raise WebSessionStateError(f"{field} contains NUL")
    return value


def normalize_cookie(cookie: Mapping[str, object]) -> dict[str, object]:
    """Normalize requests/Playwright-shaped cookies into one strict schema."""

    name = _bounded_text(
        cookie.get("name"),
        MAX_COOKIE_NAME_BYTES,
        field="cookie.name",
        allow_empty=False,
    )
    if _COOKIE_NAME.fullmatch(name) is None:
        raise WebSessionStateError("cookie.name is invalid")
    value = _bounded_text(
        cookie.get("value"),
        MAX_COOKIE_VALUE_BYTES,
        field="cookie.value",
    )
    domain = _bounded_text(
        cookie.get("domain", ""),
        MAX_COOKIE_DOMAIN_BYTES,
        field="cookie.domain",
    ).casefold()
    path = _bounded_text(
        cookie.get("path", "/"),
        MAX_COOKIE_PATH_BYTES,
        field="cookie.path",
        allow_empty=False,
    )
    if not path.startswith("/"):
        raise WebSessionStateError("cookie.path must start with '/'")

    expires_value = cookie.get("expires")
    if expires_value is None:
        expires: float | None = None
    elif (
        isinstance(expires_value, bool)
        or not isinstance(expires_value, (int, float))
    ):
        raise WebSessionStateError("cookie.expires must be numeric or null")
    else:
        expires = float(expires_value)
        if not -1 <= expires <= 253402300799:
            raise WebSessionStateError("cookie.expires is outside bounds")
        if expires < 0:
            expires = None

    http_only = cookie.get("http_only", cookie.get("httpOnly", False))
    secure = cookie.get("secure", False)
    if not isinstance(http_only, bool) or not isinstance(secure, bool):
        raise WebSessionStateError(
            "cookie http_only and secure fields must be booleans"
        )
    same_site_value = cookie.get("same_site", cookie.get("sameSite"))
    if same_site_value in (None, ""):
        same_site: str | None = None
    elif not isinstance(same_site_value, str):
        raise WebSessionStateError("cookie.same_site must be a string or null")
    else:
        canonical_same_site = same_site_value.casefold()
        same_site_map = {
            "lax": "Lax",
            "none": "None",
            "strict": "Strict",
        }
        if canonical_same_site not in same_site_map:
            raise WebSessionStateError("cookie.same_site is invalid")
        same_site = same_site_map[canonical_same_site]

    return {
        "name": name,
        "value": value,
        "domain": domain,
        "path": path,
        "expires": expires,
        "http_only": http_only,
        "secure": secure,
        "same_site": same_site,
    }


def normalize_cookies(
    cookies: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    if isinstance(cookies, (str, bytes)) or not isinstance(cookies, Sequence):
        raise WebSessionStateError("cookies must be a sequence")
    if len(cookies) > MAX_COOKIE_COUNT:
        raise WebSessionStateError(
            f"cookie count exceeds {MAX_COOKIE_COUNT}"
        )
    unique: dict[tuple[str, str, str], dict[str, object]] = {}
    for item in cookies:
        if not isinstance(item, Mapping):
            raise WebSessionStateError("each cookie must be an object")
        normalized = normalize_cookie(item)
        key = (
            str(normalized["name"]),
            str(normalized["domain"]),
            str(normalized["path"]),
        )
        unique[key] = normalized
    return [unique[key] for key in sorted(unique)]


def _cookie_key(cookie: Mapping[str, object]) -> tuple[str, str, str]:
    return (
        str(cookie["name"]),
        str(cookie["domain"]),
        str(cookie["path"]),
    )


def _security_kind(name: str) -> str | None:
    lowered = name.casefold()
    if "csrf" in lowered or "xsrf" in lowered:
        return "csrf"
    if "jwt" in lowered:
        return "jwt"
    if (
        "session" in lowered
        or "sess" in lowered
        or "auth" in lowered
        or "token" in lowered
    ):
        return "session"
    return None


def _security_header_kind(name: str) -> str | None:
    lowered = name.casefold()
    exact = _SECURITY_HEADER_KINDS.get(lowered)
    if exact is not None:
        return exact
    if "cookie" in lowered:
        return "cookie"
    if "csrf" in lowered or "xsrf" in lowered:
        return "csrf"
    if "jwt" in lowered:
        return "jwt"
    if (
        "authorization" in lowered
        or lowered.endswith("-auth")
        or "token" in lowered
        or "api-key" in lowered
        or "apikey" in lowered
        or "session-id" in lowered
        or "secret" in lowered
    ):
        return "authorization"
    return None


def cookie_transition(
    before: Sequence[Mapping[str, object]],
    after: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    """Return a value-free description of one cookie-jar transition."""

    old = {_cookie_key(item): item for item in before}
    new = {_cookie_key(item): item for item in after}
    created = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    rotated = sorted(
        key
        for key in set(old) & set(new)
        if old[key]["value"] != new[key]["value"]
    )
    updated = sorted(
        key
        for key in set(old) & set(new)
        if old[key]["value"] == new[key]["value"]
        and old[key] != new[key]
    )

    def public_key(key: tuple[str, str, str]) -> dict[str, str]:
        return {"name": key[0], "domain": key[1], "path": key[2]}

    security_material: list[dict[str, str]] = []
    for action, keys in (
        ("created", created),
        ("rotated", rotated),
        ("updated", updated),
        ("removed", removed),
    ):
        for key in keys:
            kind = _security_kind(key[0])
            if kind is not None:
                security_material.append(
                    {
                        "kind": kind,
                        "name": key[0],
                        "action": action,
                    }
                )
    return {
        "before_count": len(old),
        "after_count": len(new),
        "created": [public_key(key) for key in created],
        "rotated": [public_key(key) for key in rotated],
        "updated": [public_key(key) for key in updated],
        "removed": [public_key(key) for key in removed],
        "security_material": security_material,
    }


def sanitize_url(url: str) -> dict[str, object]:
    """Retain routing structure without query values or userinfo."""

    bounded = _bounded_text(url, MAX_URL_BYTES, field="url", allow_empty=False)
    try:
        parts = urlsplit(bounded)
        hostname = parts.hostname or ""
        parsed_port = parts.port
    except ValueError as error:
        raise WebSessionStateError("url is structurally invalid") from error
    if parts.scheme.casefold() not in {"http", "https"} or not hostname:
        raise WebSessionStateError("url must be an absolute HTTP URL")
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    port = f":{parsed_port}" if parsed_port is not None else ""
    authority = f"{hostname}{port}"
    query_names = sorted(
        {
            key
            for key, _value in parse_qsl(
                parts.query,
                keep_blank_values=True,
            )
        }
    )
    safe_segments: list[str] = []
    redacted_path_segment = False
    for segment in parts.path.split("/"):
        if (
            len(segment.encode("utf-8")) >= 24
            and re.fullmatch(r"[A-Za-z0-9._~%+=-]+", segment) is not None
        ):
            safe_segments.append("<redacted-segment>")
            redacted_path_segment = True
        else:
            safe_segments.append(segment)
    redacted = urlunsplit(
        (
            parts.scheme.casefold(),
            authority,
            "/".join(safe_segments),
            "&".join(f"{key}=<redacted>" for key in query_names),
            "",
        )
    )
    return {
        "url": redacted,
        "query_names": query_names,
        "had_userinfo": parts.username is not None,
        "fragment_removed": bool(parts.fragment),
        "path_segment_redacted": redacted_path_segment,
    }


def security_header_observations(
    headers: Mapping[str, object],
    *,
    location: str,
) -> list[dict[str, str]]:
    """Describe sensitive headers by name and kind, without their values."""

    observations: list[dict[str, str]] = []
    for name in list(headers)[:MAX_HEADER_COUNT]:
        lowered = str(name).casefold()
        kind = _security_header_kind(lowered)
        if kind is not None:
            observations.append(
                {"location": location, "name": lowered, "kind": kind}
            )
    return observations


def redact_headers(headers: Mapping[str, object]) -> dict[str, str]:
    """Bound headers while replacing credential-bearing values."""

    redacted: dict[str, str] = {}
    for name, raw_value in list(headers.items())[:MAX_HEADER_COUNT]:
        encoded_name = str(name).encode("utf-8", errors="replace")
        clean_name = encoded_name[:256].decode("utf-8", errors="replace")
        if not clean_name:
            continue
        if _security_header_kind(clean_name) is not None:
            clean_value = "<redacted>"
        else:
            encoded = str(raw_value).encode("utf-8", errors="replace")
            clean_value = encoded[:4096].decode("utf-8", errors="replace")
        redacted[clean_name] = clean_value
    return redacted


def _private_atomic_write(descriptor: int, name: str, data: bytes) -> None:
    if not name or "/" in name or name in {".", ".."}:
        raise WebSessionStateError("artifact name must be one component")
    temporary = f".{name}.tmp-{os.getpid()}-{secrets.token_hex(6)}"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    output = os.open(temporary, flags, 0o600, dir_fd=descriptor)
    try:
        view = memoryview(data)
        while view:
            written = os.write(output, view)
            view = view[written:]
        os.fsync(output)
    except BaseException:
        os.close(output)
        os.unlink(temporary, dir_fd=descriptor)
        raise
    else:
        os.close(output)
    try:
        os.replace(
            temporary,
            name,
            src_dir_fd=descriptor,
            dst_dir_fd=descriptor,
        )
        os.fsync(descriptor)
    except BaseException:
        try:
            os.unlink(temporary, dir_fd=descriptor)
        except FileNotFoundError:
            pass
        raise


def _read_private_json(
    descriptor: int,
    name: str,
    maximum_bytes: int,
) -> object | None:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        source = os.open(name, flags, dir_fd=descriptor)
    except FileNotFoundError:
        return None
    try:
        before = os.fstat(source)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > maximum_bytes
            or stat.S_IMODE(before.st_mode) & 0o077
        ):
            raise WebSessionStateError(f"{name} is not a private bounded file")
        payload = bytearray()
        while len(payload) <= maximum_bytes:
            block = os.read(
                source,
                min(64 * 1024, maximum_bytes + 1 - len(payload)),
            )
            if not block:
                break
            payload.extend(block)
        after = os.fstat(source)
        if (
            len(payload) > maximum_bytes
            or any(
                getattr(before, field) != getattr(after, field)
                for field in (
                    "st_dev",
                    "st_ino",
                    "st_mode",
                    "st_nlink",
                    "st_size",
                    "st_mtime_ns",
                    "st_ctime_ns",
                )
            )
        ):
            raise WebSessionStateError(f"{name} changed while being read")
    finally:
        os.close(source)
    try:
        return json.loads(bytes(payload))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WebSessionStateError(f"{name} is not valid JSON") from exc


class PersistentWebSession:
    """Serialize one named role's cookie state and redacted event timeline."""

    def __init__(self, output_root: Path, session_name: str) -> None:
        self.output_root = output_root
        self.session_name = validate_session_name(session_name)
        self._root_descriptor: int | None = None
        self._sessions_descriptor: int | None = None
        self._session_descriptor: int | None = None
        self._lock_descriptor: int | None = None

    @property
    def directory(self) -> Path:
        return self.output_root / "sessions" / self.session_name

    @property
    def cookie_path(self) -> Path:
        return self.directory / COOKIE_FILE

    @property
    def timeline_path(self) -> Path:
        return self.output_root / TIMELINE_FILE

    def __enter__(self) -> "PersistentWebSession":
        sessions_path = self.output_root / "sessions"
        try:
            self._root_descriptor = open_output_dir(self.output_root)
            self._sessions_descriptor = open_output_dir(sessions_path)
            self._session_descriptor = open_output_dir(
                sessions_path / self.session_name
            )
            flags = (
                os.O_RDWR
                | os.O_CREAT
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
            )
            self._lock_descriptor = os.open(
                LOCK_FILE,
                flags,
                0o600,
                dir_fd=self._session_descriptor,
            )
            lock_metadata = os.fstat(self._lock_descriptor)
            if (
                not stat.S_ISREG(lock_metadata.st_mode)
                or lock_metadata.st_nlink != 1
                or stat.S_IMODE(lock_metadata.st_mode) & 0o077
            ):
                raise WebSessionStateError("session lock is unsafe")
            fcntl.flock(self._lock_descriptor, fcntl.LOCK_EX)
        except BaseException:
            self.close()
            raise
        return self

    def __exit__(
        self,
        _error_type: object,
        _error: object,
        _traceback: object,
    ) -> None:
        self.close()

    def close(self) -> None:
        if self._lock_descriptor is not None:
            try:
                fcntl.flock(self._lock_descriptor, fcntl.LOCK_UN)
            finally:
                os.close(self._lock_descriptor)
                self._lock_descriptor = None
        if self._session_descriptor is not None:
            os.close(self._session_descriptor)
            self._session_descriptor = None
        if self._sessions_descriptor is not None:
            os.close(self._sessions_descriptor)
            self._sessions_descriptor = None
        if self._root_descriptor is not None:
            os.close(self._root_descriptor)
            self._root_descriptor = None

    def _descriptor(self) -> int:
        if self._session_descriptor is None or self._lock_descriptor is None:
            raise WebSessionStateError("session is not open")
        return self._session_descriptor

    def load_cookies(self) -> list[dict[str, object]]:
        document = _read_private_json(
            self._descriptor(),
            COOKIE_FILE,
            MAX_COOKIE_FILE_BYTES,
        )
        if document is None:
            return []
        if (
            not isinstance(document, dict)
            or document.get("schema_version") != SCHEMA_VERSION
            or document.get("session") != self.session_name
        ):
            raise WebSessionStateError("cookie jar envelope is invalid")
        cookies = document.get("cookies")
        if not isinstance(cookies, list):
            raise WebSessionStateError("cookie jar cookies must be a list")
        return normalize_cookies(cookies)

    def save_cookies(
        self, cookies: Sequence[Mapping[str, object]]
    ) -> list[dict[str, object]]:
        normalized = normalize_cookies(cookies)
        payload = (
            json.dumps(
                {
                    "schema_version": SCHEMA_VERSION,
                    "session": self.session_name,
                    "cookies": normalized,
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        if len(payload) > MAX_COOKIE_FILE_BYTES:
            raise WebSessionStateError("cookie jar exceeds its byte limit")
        _private_atomic_write(self._descriptor(), COOKIE_FILE, payload)
        return normalized

    def record_exchange(
        self,
        *,
        source: str,
        method: str,
        url: str,
        status: int | None,
        cookies_before: Sequence[Mapping[str, object]],
        cookies_after: Sequence[Mapping[str, object]],
        request_headers: Mapping[str, object],
        response_headers: Mapping[str, object],
        artifact: str,
    ) -> dict[str, object]:
        if source not in {"http", "browser"}:
            raise WebSessionStateError("timeline source is invalid")
        clean_method = _bounded_text(
            method.upper(), 32, field="method", allow_empty=False
        )
        if status is not None and (
            isinstance(status, bool)
            or not isinstance(status, int)
            or not 100 <= status <= 599
        ):
            raise WebSessionStateError("status is invalid")
        clean_artifact = _bounded_text(
            artifact, 4096, field="artifact", allow_empty=False
        )
        normalized_before = normalize_cookies(cookies_before)
        normalized_after = normalize_cookies(cookies_after)
        event = {
            "session": self.session_name,
            "source": source,
            "method": clean_method,
            "request": sanitize_url(url),
            "status": status,
            "cookie_transition": cookie_transition(
                normalized_before, normalized_after
            ),
            "security_headers": security_header_observations(
                request_headers, location="request"
            )
            + security_header_observations(
                response_headers, location="response"
            ),
            "artifact": clean_artifact,
            "recorded_utc": datetime.now(UTC).isoformat(),
        }

        if self._root_descriptor is None:
            raise WebSessionStateError("session is not open")
        root_descriptor = self._root_descriptor
        lock_flags = (
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        timeline_lock = os.open(
            ".timeline.lock",
            lock_flags,
            0o600,
            dir_fd=root_descriptor,
        )
        try:
            lock_metadata = os.fstat(timeline_lock)
            if (
                not stat.S_ISREG(lock_metadata.st_mode)
                or lock_metadata.st_nlink != 1
                or stat.S_IMODE(lock_metadata.st_mode) & 0o077
            ):
                raise WebSessionStateError("timeline lock is unsafe")
            fcntl.flock(timeline_lock, fcntl.LOCK_EX)
            document = _read_private_json(
                root_descriptor,
                TIMELINE_FILE,
                MAX_TIMELINE_BYTES,
            )
            if document is None:
                events: list[dict[str, object]] = []
                omitted = 0
            elif (
                not isinstance(document, dict)
                or document.get("schema_version") != SCHEMA_VERSION
                or not isinstance(document.get("events"), list)
                or isinstance(document.get("omitted_events", 0), bool)
                or not isinstance(document.get("omitted_events", 0), int)
                or int(document.get("omitted_events", 0)) < 0
            ):
                raise WebSessionStateError("timeline envelope is invalid")
            else:
                events = list(document["events"])
                omitted = int(document.get("omitted_events", 0))

            previous_ordinal = (
                events[-1].get("ordinal", omitted)
                if events and isinstance(events[-1], dict)
                else omitted
            )
            if isinstance(previous_ordinal, bool) or not isinstance(
                previous_ordinal, int
            ):
                raise WebSessionStateError("timeline ordinal is invalid")
            event["ordinal"] = previous_ordinal + 1
            events.append(event)
            if len(events) > MAX_TIMELINE_EVENTS:
                drop_count = len(events) - MAX_TIMELINE_EVENTS
                events = events[drop_count:]
                omitted += drop_count

            while True:
                envelope = {
                    "schema_version": SCHEMA_VERSION,
                    "omitted_events": omitted,
                    "events": events,
                }
                payload = (
                    json.dumps(
                        envelope,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                ).encode("utf-8")
                if len(payload) <= MAX_TIMELINE_BYTES:
                    break
                if len(events) <= 1:
                    raise WebSessionStateError(
                        "one timeline event exceeds bounds"
                    )
                events.pop(0)
                omitted += 1
            _private_atomic_write(
                root_descriptor,
                TIMELINE_FILE,
                payload,
            )
        finally:
            try:
                fcntl.flock(timeline_lock, fcntl.LOCK_UN)
            finally:
                os.close(timeline_lock)
        return event


__all__ = [
    "COOKIE_FILE",
    "MAX_COOKIE_COUNT",
    "MAX_TIMELINE_EVENTS",
    "PersistentWebSession",
    "SCHEMA_VERSION",
    "SESSION_NAMES",
    "TIMELINE_FILE",
    "WebSessionStateError",
    "cookie_transition",
    "normalize_cookie",
    "normalize_cookies",
    "redact_headers",
    "sanitize_url",
    "security_header_observations",
    "validate_session_name",
]
