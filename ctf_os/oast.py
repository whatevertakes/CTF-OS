"""Minimal provider-neutral OAST callback ledger.

The operator explicitly supplies an approved HTTPS provider base.  CTF-OS does
not create accounts or collect provider credentials; it only creates a scoped
callback identifier, polls JSON events, redacts them, and preserves receipts.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
import hashlib
import json
import os
from pathlib import Path
import secrets
from typing import Any
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

from .workspace import atomic_json, state_lock, utc_now


class OastError(ValueError):
    pass


Fetch = Callable[[str], bytes]
_SAFE_HEADERS = frozenset({"content-type", "user-agent", "host", "x-forwarded-for", "x-real-ip", "accept"})
_SECRET_WORDS = ("authorization", "cookie", "token", "secret", "credential", "session")


def create_oast(
    root: Path, *, challenge_id: str, input_fingerprint: str, branch_id: str,
    provider_base: str,
) -> dict[str, Any]:
    provider = _provider(provider_base)
    identifier = secrets.token_hex(12)
    callback = provider.rstrip("/") + "/" + quote(identifier)
    payload = {
        "schema_version": 1, "oast_id": identifier, "challenge_id": challenge_id,
        "input_fingerprint": input_fingerprint, "branch_id": branch_id,
        "provider_base": provider, "callback_url": callback,
        "created_at": utc_now(), "last_polled_at": None,
    }
    path = root / "oast" / f"{identifier}.json"
    with state_lock(root):
        atomic_json(path, payload)
    return {**payload, "record_path": str(path)}


def poll_oast(
    root: Path, *, oast_id: str, input_fingerprint: str,
    fetch: Fetch | None = None,
) -> dict[str, Any]:
    path = _record_path(root, oast_id)
    record = _read_record(path, input_fingerprint)
    endpoint = str(record["provider_base"]).rstrip("/") + "/events?id=" + quote(oast_id)
    raw = (fetch or _fetch)(endpoint)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OastError("OAST provider returned malformed JSON") from exc
    rows = payload.get("events", []) if isinstance(payload, Mapping) else payload
    if not isinstance(rows, list):
        raise OastError("OAST provider response must be an event array")
    accepted = []
    ledger = root / "oast" / f"{oast_id}.events.jsonl"
    with state_lock(root):
        existing = {row.get("event_id") for row in _read_jsonl(ledger)}
        for raw_event in rows:
            if not isinstance(raw_event, Mapping):
                continue
            event = _sanitize_event(raw_event, branch_id=str(record["branch_id"]), oast_id=oast_id)
            if event["event_id"] in existing:
                continue
            _append_jsonl(ledger, event)
            existing.add(event["event_id"])
            accepted.append(event)
        record["last_polled_at"] = utc_now()
        atomic_json(path, record)
    return {"oast_id": oast_id, "new_events": accepted, "new_event_count": len(accepted), "polled_at": record["last_polled_at"]}


def oast_events(root: Path, *, oast_id: str, input_fingerprint: str) -> list[dict[str, Any]]:
    _read_record(_record_path(root, oast_id), input_fingerprint)
    return _read_jsonl(root / "oast" / f"{oast_id}.events.jsonl")


def _sanitize_event(raw: Mapping[str, Any], *, branch_id: str, oast_id: str) -> dict[str, Any]:
    headers = raw.get("headers") if isinstance(raw.get("headers"), Mapping) else {}
    safe_headers = {
        str(key).casefold(): _redact(str(value))[:1000]
        for key, value in headers.items() if str(key).casefold() in _SAFE_HEADERS
    }
    body = _redact(str(raw.get("body", "")))[:4096]
    material = {
        "method": str(raw.get("method", "UNKNOWN"))[:32],
        "received_at": str(raw.get("received_at") or utc_now()),
        "source": _redact(str(raw.get("source", "unknown")))[:256],
        "headers": safe_headers, "body": body,
    }
    identifier = str(raw.get("event_id") or hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:24])
    return {
        "event_id": identifier, "oast_id": oast_id, "branch_id": branch_id,
        **material,
    }


def _provider(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise OastError("approved OAST provider must be a credential-free HTTPS base URL")
    host = parsed.hostname.casefold()
    if host in {"localhost", "metadata.google.internal", "host.docker.internal"}:
        raise OastError("local, metadata, and host-gateway OAST providers are forbidden")
    return value.rstrip("/")


def _fetch(url: str) -> bytes:
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "CTF-OS-OAST/1"})
    with urlopen(request, timeout=60) as response:  # noqa: S310 - URL was validated as explicit HTTPS provider
        return response.read(1_000_001)[:1_000_000]


def _record_path(root: Path, oast_id: str) -> Path:
    if not oast_id or not oast_id.isalnum() or len(oast_id) > 128:
        raise OastError("invalid OAST identifier")
    return root / "oast" / f"{oast_id}.json"


def _read_record(path: Path, fingerprint: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise OastError("OAST record is missing or unsafe")
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise OastError("OAST record is malformed") from exc
    if not isinstance(record, dict) or record.get("input_fingerprint") != fingerprint:
        raise OastError("OAST record belongs to a different challenge fingerprint")
    return record


def _append_jsonl(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(dict(payload), sort_keys=True, separators=(",", ":")) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    if path.is_symlink() or not path.is_file():
        raise OastError("OAST event ledger is unsafe")
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _redact(value: str) -> str:
    result = value
    for word in _SECRET_WORDS:
        result = result.replace(word, f"[{word.upper()}_REDACTED]")
        result = result.replace(word.title(), f"[{word.upper()}_REDACTED]")
    return result
