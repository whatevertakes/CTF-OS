"""Bounded, deterministic summaries of immutable tool stream evidence.

Raw stdout and stderr stay in hash-addressed artifacts.  This module exposes
only small, credential-redacted head/tail excerpts for later model context.
It deliberately never trusts ``SandboxResult.stdout_summary``: ctfwrap's
summary is a tail of the fully drained stream, while the durable artifact can
be a size-limited prefix.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import stat
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
from typing import Literal, Mapping

from ctf_os.credential_safety import (
    CREDENTIAL_KEY_PATTERN,
    KNOWN_PROVIDER_CREDENTIAL,
    host_credential_values,
)
from ctf_os.sandbox.files import (
    DEFAULT_STREAM_CAPTURE_MAX_BYTES,
    SafeFileError,
    normalize_locator,
)
from ctf_os.sandbox.types import SandboxResult
from ctf_os.terminal import terminal_safe

StreamName = Literal["stdout", "stderr"]

RECEIPT_SAMPLE_BYTES = 256
MAX_RECEIPT_SAMPLE_BYTES = 1024
MAX_RECEIPT_EXCERPT_JSON_CHARS = 512
MAX_RECEIPT_STREAM_EVIDENCE_BYTES = 4096
MAX_RECEIPT_PREVIEW_CHARS = 160
MAX_RECEIPT_ARTIFACT_ID_CHARS = 256
MAX_RECEIPT_STRUCTURE_JSON_BYTES = 1536
MAX_RECEIPT_STRUCTURE_ITEMS = 16
MAX_RECEIPT_DELIMITED_ROWS = 100_000
MAX_RECEIPT_SALIENT_LINES = 4
MAX_RECEIPT_SALIENT_LINE_JSON_CHARS = 240

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SALIENT_TEXT_MARKER = re.compile(
    r"^(?:SUMMARY|ORACLE|RESULT|RECORD|REC|ERROR|FLAG_CANDIDATE)(?::| )"
)
# Keep generated HTML tag keys inside the receipt-state validation contract.
# ``HTMLParser`` is deliberately best effort over arbitrary challenge output
# and can interpret source-code fragments such as ``<snail_id; ...>`` as tag
# names even though they are not safe structured identifiers.
_HTML_SUMMARY_TAG = re.compile(r"^[a-z0-9:_-]{1,64}$")
_CREDENTIAL_KEY = CREDENTIAL_KEY_PATTERN
_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?im)"
    rf"((?<![A-Za-z0-9_])[\"']?{_CREDENTIAL_KEY}"
    r"[\"']?[ \t]*[:=][ \t]*)"
    r"([^\r\n]*)"
)
_COMMAND_CREDENTIAL = re.compile(
    r"(?i)"
    rf"(\B--{_CREDENTIAL_KEY}[ \t]+)"
    r"([^\s]+)"
)
_BEARER = re.compile(
    r"(?i)(\bbearer[ \t]+)[A-Za-z0-9._~+/=-]{4,}"
)
_JWT = re.compile(
    r"\beyJ[A-Za-z0-9_-]{4,}\."
    r"[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b"
)
_CREDENTIAL_QUERY = re.compile(
    r"(?i)"
    r"([?&](?:"
    r"access_token|refresh_token|token|api[_-]?key|"
    r"secret|password|passwd"
    r")=)"
    r"[^&#\s]*"
)
_URL_USERINFO = re.compile(
    r"(?i)(\b[a-z][a-z0-9+.-]*://)"
    r"[^/\s:@]+:[^/\s@]+@"
)
_PRIVATE_KEY = re.compile(
    r"(?is)"
    r"-----BEGIN[ \t]+[A-Z0-9 ]*PRIVATE KEY-----"
    r".*?"
    r"(?:-----END[ \t]+[A-Z0-9 ]*PRIVATE KEY-----|$)"
)
_KNOWN_CREDENTIAL_TOKEN = KNOWN_PROVIDER_CREDENTIAL
_SENSITIVE_CONTEXT_PATTERNS = (
    _CREDENTIAL_ASSIGNMENT,
    _COMMAND_CREDENTIAL,
    _BEARER,
    _JWT,
    _CREDENTIAL_QUERY,
    _URL_USERINFO,
    _PRIVATE_KEY,
    _KNOWN_CREDENTIAL_TOKEN,
)


class ReceiptSummaryError(ValueError):
    """An immutable stream artifact cannot support a trustworthy summary."""


def _environment_secret_values() -> tuple[str, ...]:
    """Return host credential values that must never enter model context.

    Sandbox commands do not receive the host environment, but this additional
    boundary also protects operator-supplied output and test doubles from
    echoing a credential already present in the engine process.  Short values
    are excluded because they create broad, low-signal replacements such as
    redacting every occurrence of ``true``.
    """

    return host_credential_values()


def _validate_artifact_identity(
    artifact_id: str,
    artifact_path: str,
    artifact_sha256: str,
) -> tuple[str, str, str]:
    if (
        not isinstance(artifact_id, str)
        or not artifact_id
        or len(artifact_id) > MAX_RECEIPT_ARTIFACT_ID_CHARS
        or any(ord(character) < 0x20 for character in artifact_id)
    ):
        raise ReceiptSummaryError("artifact_id is not a bounded identifier")
    try:
        normalized_path = normalize_locator(artifact_path)
    except SafeFileError as error:
        raise ReceiptSummaryError("artifact_path is not a safe locator") from error
    normalized_sha256 = str(artifact_sha256).lower()
    if not _SHA256.fullmatch(normalized_sha256):
        raise ReceiptSummaryError("artifact_sha256 is not a SHA-256 digest")
    return artifact_id, normalized_path, normalized_sha256


def _read_verified_samples(
    snapshot_path: Path,
    *,
    expected_sha256: str,
    sample_bytes: int,
    maximum_snapshot_bytes: int,
) -> tuple[int, bytes, bytes, bool, bool, bytes]:
    if (
        isinstance(sample_bytes, bool)
        or not isinstance(sample_bytes, int)
        or not 1 <= sample_bytes <= MAX_RECEIPT_SAMPLE_BYTES
    ):
        raise ReceiptSummaryError(
            f"sample_bytes must be between 1 and {MAX_RECEIPT_SAMPLE_BYTES}"
        )
    if (
        isinstance(maximum_snapshot_bytes, bool)
        or not isinstance(maximum_snapshot_bytes, int)
        or not 1
        <= maximum_snapshot_bytes
        <= DEFAULT_STREAM_CAPTURE_MAX_BYTES
    ):
        raise ReceiptSummaryError(
            "maximum_snapshot_bytes is outside the stream capture bound"
        )

    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(Path(snapshot_path), flags)
    except OSError as error:
        raise ReceiptSummaryError(
            "immutable stream snapshot cannot be opened safely"
        ) from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ReceiptSummaryError(
                "immutable stream snapshot is not a regular file"
            )
        if before.st_mode & 0o222:
            raise ReceiptSummaryError(
                "stream snapshot is writable instead of immutable"
            )
        if not 0 <= before.st_size <= maximum_snapshot_bytes:
            raise ReceiptSummaryError(
                "stream snapshot exceeds the receipt summary bound"
            )

        digest = hashlib.sha256()
        snapshot_payload = bytearray()
        offset = 0
        while offset < before.st_size:
            block = os.pread(
                descriptor,
                min(1024 * 1024, before.st_size - offset),
                offset,
            )
            if not block:
                raise ReceiptSummaryError(
                    "stream snapshot ended before its recorded size"
                )
            digest.update(block)
            snapshot_payload.extend(block)
            offset += len(block)

        head_size = min(sample_bytes, before.st_size)
        head = bytes(snapshot_payload[:head_size])
        if before.st_size <= sample_bytes * 2:
            tail = b""
            tail_start = before.st_size
        else:
            tail_start = before.st_size - sample_bytes
            tail = bytes(snapshot_payload[tail_start:])

        after = os.fstat(descriptor)
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(
            getattr(before, field) != getattr(after, field)
            for field in stable_fields
        ):
            raise ReceiptSummaryError(
                "stream snapshot changed while it was summarized"
            )
        if digest.hexdigest() != expected_sha256:
            raise ReceiptSummaryError("stream snapshot SHA-256 mismatch")
        (
            head_requires_omission,
            tail_requires_omission,
        ) = _sensitive_context_omissions(
            bytes(snapshot_payload),
            head_end=head_size,
            tail_start=tail_start,
        )
        return (
            before.st_size,
            head,
            tail,
            head_requires_omission,
            tail_requires_omission,
            bytes(snapshot_payload),
        )
    finally:
        os.close(descriptor)


def _sensitive_context_omissions(
    snapshot_payload: bytes,
    *,
    head_end: int,
    tail_start: int,
) -> tuple[bool, bool]:
    """Identify sensitive spans crossing either retained sample boundary.

    Isolated sample redaction is unsafe when only part of a credential, URL
    userinfo span, JWT, or private-key block is retained.  Analyze the already
    bounded and verified immutable snapshot so a match crossing either byte
    boundary causes that complete sample text to be omitted.  If byte-to-text
    boundary mapping is uncertain, fail closed for the affected sample.
    """

    payload_size = len(snapshot_payload)
    head_has_boundary = 0 < head_end < payload_size
    tail_has_boundary = 0 < tail_start < payload_size
    if not head_has_boundary and not tail_has_boundary:
        return False, False
    try:
        complete_text = snapshot_payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return head_has_boundary, tail_has_boundary

    def character_boundary(byte_boundary: int) -> int | None:
        try:
            return len(
                snapshot_payload[:byte_boundary].decode(
                    "utf-8",
                    errors="strict",
                )
            )
        except UnicodeDecodeError:
            return None

    head_character_end = (
        character_boundary(head_end) if head_has_boundary else None
    )
    tail_character_start = (
        character_boundary(tail_start) if tail_has_boundary else None
    )
    head_omitted = head_has_boundary and head_character_end is None
    tail_omitted = tail_has_boundary and tail_character_start is None
    for pattern in _SENSITIVE_CONTEXT_PATTERNS:
        for match in pattern.finditer(complete_text):
            if (
                head_character_end is not None
                and match.start() < head_character_end < match.end()
            ):
                head_omitted = True
            if (
                tail_character_start is not None
                and match.start() < tail_character_start < match.end()
            ):
                tail_omitted = True
            if head_omitted and tail_omitted:
                return True, True
    for secret in _environment_secret_values():
        start = 0
        while True:
            secret_start = complete_text.find(secret, start)
            if secret_start < 0:
                break
            secret_end = secret_start + len(secret)
            if (
                head_character_end is not None
                and secret_start < head_character_end < secret_end
            ):
                head_omitted = True
            if (
                tail_character_start is not None
                and secret_start < tail_character_start < secret_end
            ):
                tail_omitted = True
            if head_omitted and tail_omitted:
                return True, True
            start = secret_start + 1
    return head_omitted, tail_omitted


def _json_string_size(value: str) -> int:
    return len(json.dumps(value, ensure_ascii=True, separators=(",", ":")))


def _bounded_json_text(
    value: str,
    maximum_json_chars: int = MAX_RECEIPT_EXCERPT_JSON_CHARS,
) -> tuple[str, bool]:
    if _json_string_size(value) <= maximum_json_chars:
        return value, False
    suffix = "…"
    low = 0
    high = len(value)
    while low < high:
        middle = (low + high + 1) // 2
        candidate = value[:middle] + suffix
        if _json_string_size(candidate) <= maximum_json_chars:
            low = middle
        else:
            high = middle - 1
    return value[:low] + suffix, True


def _bounded_ascii_json_text(
    value: str,
    maximum_json_chars: int,
) -> tuple[str, bool]:
    """Bound already-redacted ASCII text with an ASCII-only suffix."""

    if _json_string_size(value) <= maximum_json_chars:
        return value, False
    suffix = "..."
    low = 0
    high = len(value)
    while low < high:
        middle = (low + high + 1) // 2
        candidate = value[:middle] + suffix
        if _json_string_size(candidate) <= maximum_json_chars:
            low = middle
        else:
            high = middle - 1
    return value[:low] + suffix, True


def _redact_credentials(value: str) -> tuple[str, int]:
    redactions = 0

    def replace_assignment(match: re.Match[str]) -> str:
        nonlocal redactions
        redactions += 1
        return match.group(1) + "[REDACTED]"

    def replace_one(match: re.Match[str]) -> str:
        nonlocal redactions
        redactions += 1
        return match.group(1) + "[REDACTED]"

    def replace_jwt(_match: re.Match[str]) -> str:
        nonlocal redactions
        redactions += 1
        return "[REDACTED_JWT]"

    def replace_private_key(_match: re.Match[str]) -> str:
        nonlocal redactions
        redactions += 1
        return "[REDACTED_PRIVATE_KEY]"

    def replace_known_token(_match: re.Match[str]) -> str:
        nonlocal redactions
        redactions += 1
        return "[REDACTED_TOKEN]"

    result = value
    for secret in _environment_secret_values():
        occurrences = result.count(secret)
        if occurrences:
            result = result.replace(secret, "[REDACTED_ENV]")
            redactions += occurrences
    result = _PRIVATE_KEY.sub(replace_private_key, result)
    result = _CREDENTIAL_ASSIGNMENT.sub(replace_assignment, result)
    result = _COMMAND_CREDENTIAL.sub(replace_assignment, result)
    result = _BEARER.sub(replace_one, result)
    result = _JWT.sub(replace_jwt, result)
    result = _CREDENTIAL_QUERY.sub(replace_one, result)
    result = _URL_USERINFO.sub(replace_one, result)
    result = _KNOWN_CREDENTIAL_TOKEN.sub(replace_known_token, result)
    return result, redactions


def _structured_text(value: object) -> str:
    redacted, _redactions = _redact_credentials(str(value))
    safe = terminal_safe(redacted, multiline=False)
    bounded, _truncated = _bounded_json_text(safe, 96)
    return bounded


def _json_type(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "unknown"


class _BoundedHTMLSummaryParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: Counter[str] = Counter()
        self._in_title = False
        self._title_parts: list[str] = []
        self._title_chars = 0

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        del attrs
        normalized = tag.casefold()
        if normalized in self.tags or len(self.tags) < 256:
            self.tags[normalized] += 1
        if normalized == "title":
            self._in_title = True

    def handle_startendtag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if not self._in_title or self._title_chars >= 512:
            return
        retained = data[: 512 - self._title_chars]
        self._title_parts.append(retained)
        self._title_chars += len(retained)

    @property
    def title(self) -> str | None:
        value = " ".join("".join(self._title_parts).split())
        return _structured_text(value) if value else None


def _base_structured_summary(
    *,
    kind: str,
    scope: str,
    bytes_analyzed: int,
) -> dict[str, object]:
    return {
        "version": 1,
        "kind": kind,
        "scope": scope,
        "bytes_analyzed": bytes_analyzed,
        "details_omitted": False,
    }


def _bounded_structured_summary(
    summary: dict[str, object],
) -> dict[str, object]:
    encoded = json.dumps(
        summary,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("ascii")
    if len(encoded) <= MAX_RECEIPT_STRUCTURE_JSON_BYTES:
        return summary
    return {
        "version": 1,
        "kind": summary["kind"],
        "scope": summary["scope"],
        "bytes_analyzed": summary["bytes_analyzed"],
        "details_omitted": True,
    }


def _structured_json_summary(
    parsed: object,
    *,
    scope: str,
    bytes_analyzed: int,
) -> dict[str, object]:
    summary = _base_structured_summary(
        kind="json",
        scope=scope,
        bytes_analyzed=bytes_analyzed,
    )
    summary["top_level"] = _json_type(parsed)
    if isinstance(parsed, dict):
        keys = sorted(parsed)
        retained_types: dict[str, str] = {}
        for key in keys:
            projected = _structured_text(key)
            if projected in retained_types:
                continue
            retained_types[projected] = _json_type(parsed[key])
            if len(retained_types) >= MAX_RECEIPT_STRUCTURE_ITEMS:
                break
        summary["key_count"] = len(keys)
        summary["key_types"] = retained_types
        summary["keys_omitted"] = len(keys) - len(retained_types)
    elif isinstance(parsed, list):
        summary["item_count"] = len(parsed)
        summary["item_types"] = sorted(
            {_json_type(item) for item in parsed}
        )
    return _bounded_structured_summary(summary)


def _structured_html_summary(
    text: str,
    *,
    scope: str,
    bytes_analyzed: int,
    http_status: str | None,
) -> dict[str, object]:
    parser = _BoundedHTMLSummaryParser()
    try:
        parser.feed(text)
        parser.close()
    except (AssertionError, ValueError):
        # HTMLParser is intentionally best effort over hostile, malformed
        # challenge output. The raw immutable pointer remains authoritative.
        pass
    valid_tags = [
        (tag, count)
        for tag, count in parser.tags.items()
        if _HTML_SUMMARY_TAG.fullmatch(tag) is not None
    ]
    retained_tags = sorted(
        valid_tags,
        key=lambda item: (-item[1], item[0]),
    )[:MAX_RECEIPT_STRUCTURE_ITEMS]
    summary = _base_structured_summary(
        kind="html",
        scope=scope,
        bytes_analyzed=bytes_analyzed,
    )
    summary.update(
        {
            "http_status": (
                _structured_text(http_status)
                if http_status is not None
                else None
            ),
            "title": parser.title,
            "tag_counts": dict(retained_tags),
            "tags_omitted": max(0, len(parser.tags) - len(retained_tags)),
        }
    )
    return _bounded_structured_summary(summary)


def _structured_delimited_summary(
    text: str,
    *,
    delimiter: str,
    scope: str,
    bytes_analyzed: int,
) -> dict[str, object] | None:
    try:
        reader = csv.reader(io.StringIO(text), delimiter=delimiter)
        header = next(reader)
        if len(header) < 2:
            return None
        row_count = 0
        consistent_rows = 0
        for row in reader:
            if not row or (len(row) == 1 and not row[0]):
                continue
            row_count += 1
            if len(row) == len(header):
                consistent_rows += 1
            if row_count >= MAX_RECEIPT_DELIMITED_ROWS:
                break
    except (csv.Error, StopIteration):
        return None
    if row_count < 1 or consistent_rows * 4 < row_count * 3:
        return None
    retained = header[:MAX_RECEIPT_STRUCTURE_ITEMS]
    summary = _base_structured_summary(
        kind="delimited_text",
        scope=scope,
        bytes_analyzed=bytes_analyzed,
    )
    summary.update(
        {
            "delimiter": "tab" if delimiter == "\t" else "comma",
            "columns": [_structured_text(value) for value in retained],
            "columns_omitted": len(header) - len(retained),
            "row_count": row_count,
            "row_count_exact": (
                row_count < MAX_RECEIPT_DELIMITED_ROWS
                and scope == "complete_stream"
            ),
        }
    )
    return _bounded_structured_summary(summary)


def _structured_content_summary(
    payload: bytes,
    *,
    coverage: str,
) -> dict[str, object]:
    scope = {
        "complete_stream": "complete_stream",
        "retained_prefix_only": "retained_prefix",
    }.get(coverage, "stored_snapshot")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return _base_structured_summary(
            kind="binary",
            scope=scope,
            bytes_analyzed=len(payload),
        )

    stripped = text.strip()
    if coverage == "complete_stream" and stripped:
        try:
            parsed = json.loads(stripped)
        except (json.JSONDecodeError, RecursionError, ValueError):
            pass
        else:
            return _structured_json_summary(
                parsed,
                scope=scope,
                bytes_analyzed=len(payload),
            )

    http_status: str | None = None
    html_text = text
    first_line = text.splitlines()[0] if text.splitlines() else ""
    if re.fullmatch(r"HTTP/\d(?:\.\d)?[ \t]+\d{3}(?:[ \t]+.*)?", first_line):
        http_status = first_line
        partition = (
            text.partition("\r\n\r\n")
            if "\r\n\r\n" in text
            else text.partition("\n\n")
        )
        if partition[1]:
            html_text = partition[2]
    if re.search(
        r"(?is)<!doctype[ \t]+html\b|"
        r"<(?:html|head|body|title|table|script|style)\b",
        html_text,
    ):
        return _structured_html_summary(
            html_text,
            scope=scope,
            bytes_analyzed=len(payload),
            http_status=http_status,
        )

    for delimiter in ("\t", ","):
        if delimiter not in text:
            continue
        summary = _structured_delimited_summary(
            text,
            delimiter=delimiter,
            scope=scope,
            bytes_analyzed=len(payload),
        )
        if summary is not None:
            return summary

    line_count = text.count("\n") + bool(text and not text.endswith("\n"))
    nonempty_line_count = sum(
        1 for line in text.splitlines() if line.strip()
    )
    summary = _base_structured_summary(
        kind="text",
        scope=scope,
        bytes_analyzed=len(payload),
    )
    summary.update(
        {
            "line_count": line_count,
            "line_count_exact": scope == "complete_stream",
            "nonempty_line_count": nonempty_line_count,
        }
    )
    salient_lines, salient_lines_omitted = _salient_text_lines(
        text,
        complete_stream=scope == "complete_stream",
    )
    if salient_lines:
        # Structured-summary v1 remains frozen for replay compatibility.
        # Only text summaries carrying bounded, explicitly marked records use
        # v2; consumers and state validation accept both versions exactly.
        summary["version"] = 2
        summary["salient_lines"] = salient_lines
        summary["salient_lines_omitted"] = salient_lines_omitted
    return _bounded_structured_summary(summary)


def _salient_text_lines(
    text: str,
    *,
    complete_stream: bool,
) -> tuple[list[str], int]:
    """Retain only explicit, redacted, bounded records from generic text.

    This intentionally does not infer domain semantics.  A challenge-controlled
    stream can contain arbitrary prose, so only anchored marker records are
    eligible.  The immutable raw artifact remains authoritative.
    """

    redacted, _redactions = _redact_credentials(text)
    edge = MAX_RECEIPT_SALIENT_LINES // 2
    first: list[str] = []
    tail: list[str] = []
    eligible_count = 0
    for raw_line in io.StringIO(redacted, newline=None):
        terminated = raw_line.endswith(("\n", "\r"))
        if not complete_stream and not terminated:
            # A retained-prefix or otherwise incomplete snapshot can end
            # inside a record. Never project that trailing fragment as
            # complete evidence.
            continue
        line = raw_line.rstrip("\r\n")
        if _SALIENT_TEXT_MARKER.match(line) is None:
            continue
        if not line.isascii() or any(
            character != "\t" and not 0x20 <= ord(character) <= 0x7E
            for character in line
        ):
            continue
        # Credential redaction has already examined the complete line. Limit
        # the terminal renderer's input so one adversarial marker line cannot
        # amplify host memory through a per-character output list.
        source_truncated = len(line) > MAX_RECEIPT_SALIENT_LINE_JSON_CHARS
        safe = terminal_safe(
            line[:MAX_RECEIPT_SALIENT_LINE_JSON_CHARS],
            multiline=False,
        )
        bounded, _truncated = _bounded_ascii_json_text(
            safe + ("..." if source_truncated else ""),
            MAX_RECEIPT_SALIENT_LINE_JSON_CHARS,
        )
        eligible_count += 1
        if bounded in first or bounded in tail:
            continue
        if len(first) < edge:
            first.append(bounded)
            continue
        tail.append(bounded)
        if len(tail) > edge:
            tail.pop(0)

    retained = first + tail
    return retained, max(0, eligible_count - len(retained))


def _text_sample(value: bytes) -> tuple[str | None, int]:
    if not value:
        return "", 0
    try:
        decoded = value.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None, 0
    disallowed_controls = sum(
        1
        for character in decoded
        if (
            ord(character) < 0x20
            and character not in {"\n", "\r", "\t"}
        )
        or 0x7F <= ord(character) <= 0x9F
    )
    if "\x00" in decoded or disallowed_controls * 20 > max(1, len(decoded)):
        return None, 0
    redacted, redactions = _redact_credentials(decoded)
    return terminal_safe(redacted, multiline=True), redactions


def _sample_record(
    payload: bytes,
    *,
    byte_start: int,
    byte_end: int,
    omit_text: bool = False,
) -> tuple[dict[str, object], int, bool]:
    if omit_text:
        return (
            {
                "byte_start": byte_start,
                "byte_end": byte_end,
                "encoding": "binary-omitted",
                "sample_sha256": hashlib.sha256(payload).hexdigest(),
            },
            0,
            True,
        )
    text, redactions = _text_sample(payload)
    if text is None:
        return (
            {
                "byte_start": byte_start,
                "byte_end": byte_end,
                "encoding": "binary-omitted",
                "sample_sha256": hashlib.sha256(payload).hexdigest(),
            },
            redactions,
            True,
        )
    bounded, truncated = _bounded_json_text(text)
    return (
        {
            "byte_start": byte_start,
            "byte_end": byte_end,
            "encoding": "utf-8",
            "text": bounded,
            "text_truncated": truncated,
        },
        redactions,
        False,
    )


def _stream_metadata(
    result: SandboxResult,
    stream: StreamName,
    *,
    stored_bytes: int,
) -> dict[str, object]:
    drained_bytes = getattr(result, f"{stream}_bytes")
    reported_stored_bytes = getattr(result, f"{stream}_stored_bytes")
    limit_bytes = getattr(result, f"{stream}_limit_bytes")
    truncated = getattr(result, f"{stream}_truncated")
    truncation_known = getattr(result, f"{stream}_truncation_known")
    capture_complete = getattr(result, f"{stream}_capture_complete")
    summary_truncated = getattr(result, f"{stream}_summary_truncated")
    stream_error = getattr(result, f"{stream}_error")

    for name, number in (
        ("drained_bytes", drained_bytes),
        ("reported_stored_bytes", reported_stored_bytes),
        ("limit_bytes", limit_bytes),
    ):
        if number is not None and (
            isinstance(number, bool)
            or not isinstance(number, int)
            or number < 0
        ):
            raise ReceiptSummaryError(f"{stream} {name} is invalid")
    if stored_bytes > drained_bytes:
        raise ReceiptSummaryError(
            f"{stream} immutable snapshot exceeds drained byte count"
        )
    if (
        reported_stored_bytes is not None
        and reported_stored_bytes != stored_bytes
    ):
        raise ReceiptSummaryError(
            f"{stream} stored byte count does not match immutable snapshot"
        )
    if limit_bytes is not None and stored_bytes > limit_bytes:
        raise ReceiptSummaryError(
            f"{stream} immutable snapshot exceeds its capture limit"
        )
    if truncation_known and truncated is None:
        raise ReceiptSummaryError(
            f"{stream} truncation is marked known without a value"
        )
    if capture_complete and not truncation_known:
        raise ReceiptSummaryError(
            f"{stream} complete capture has unknown truncation state"
        )
    if truncation_known:
        expected_truncated = drained_bytes > stored_bytes
        if truncated is not expected_truncated:
            raise ReceiptSummaryError(
                f"{stream} truncation metadata is inconsistent"
            )

    if capture_complete and not truncated and stored_bytes == drained_bytes:
        coverage = "complete_stream"
    elif stored_bytes < drained_bytes:
        coverage = "retained_prefix_only"
    elif not capture_complete and (
        reported_stored_bytes is not None or stream_error is not None
    ):
        coverage = "incomplete_capture"
    else:
        coverage = "unknown"

    return {
        "drained_bytes": drained_bytes,
        "stored_bytes": stored_bytes,
        "limit_bytes": limit_bytes,
        "capture_complete": capture_complete,
        "truncation_known": truncation_known,
        "truncated": truncated,
        "coverage": coverage,
        # The ctfwrap tail is intentionally not copied into evidence.  Keep
        # only its completeness bit for diagnostics.
        "transport_summary_truncated": summary_truncated,
        "stream_error_present": stream_error is not None,
        "capture_error_present": result.stream_capture_error is not None,
    }


def summarize_stream_snapshot(
    snapshot_path: Path,
    *,
    artifact_id: str,
    artifact_path: str,
    artifact_sha256: str,
    result: SandboxResult,
    stream: StreamName,
    sample_bytes: int = RECEIPT_SAMPLE_BYTES,
    maximum_snapshot_bytes: int = DEFAULT_STREAM_CAPTURE_MAX_BYTES,
) -> dict[str, object]:
    """Return one self-contained, pointer-backed stream evidence record."""

    if stream not in {"stdout", "stderr"}:
        raise ReceiptSummaryError("stream must be stdout or stderr")
    (
        normalized_artifact_id,
        normalized_artifact_path,
        normalized_sha256,
    ) = _validate_artifact_identity(
        artifact_id,
        artifact_path,
        artifact_sha256,
    )
    (
        stored_bytes,
        head_payload,
        tail_payload,
        head_requires_omission,
        tail_requires_omission,
        snapshot_payload,
    ) = _read_verified_samples(
        snapshot_path,
        expected_sha256=normalized_sha256,
        sample_bytes=sample_bytes,
        maximum_snapshot_bytes=maximum_snapshot_bytes,
    )
    head, head_redactions, head_binary = _sample_record(
        head_payload,
        byte_start=0,
        byte_end=len(head_payload),
        omit_text=head_requires_omission,
    )
    tail: dict[str, object] | None = None
    tail_redactions = 0
    tail_binary = False
    if tail_payload:
        tail_start = stored_bytes - len(tail_payload)
        tail, tail_redactions, tail_binary = _sample_record(
            tail_payload,
            byte_start=tail_start,
            byte_end=stored_bytes,
            omit_text=tail_requires_omission,
        )

    metadata = _stream_metadata(
        result,
        stream,
        stored_bytes=stored_bytes,
    )
    structured_summary = _structured_content_summary(
        snapshot_payload,
        coverage=str(metadata["coverage"]),
    )
    evidence: dict[str, object] = {
        "schema_version": 2,
        "stream": stream,
        "artifact_id": normalized_artifact_id,
        "path": normalized_artifact_path,
        "sha256": normalized_sha256,
        **metadata,
        "sample_policy": "immutable_snapshot_head_tail",
        "head": head,
        "tail": tail,
        "omitted_stored_bytes": max(
            0,
            stored_bytes - len(head_payload) - len(tail_payload),
        ),
        "redaction_count": head_redactions + tail_redactions,
        "binary_sample_omitted": head_binary or tail_binary,
        "structured_summary": structured_summary,
    }
    encoded = json.dumps(
        evidence,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("ascii")
    if len(encoded) > MAX_RECEIPT_STREAM_EVIDENCE_BYTES:
        raise ReceiptSummaryError(
            "stream evidence exceeds its serialized size bound"
        )
    return evidence


def build_receipt_preview(
    *,
    exit_code: int | None,
    stdout_bytes: int,
    stderr_bytes: int,
    stdout_evidence: Mapping[str, object] | None = None,
    stderr_evidence: Mapping[str, object] | None = None,
    maximum_chars: int = MAX_RECEIPT_PREVIEW_CHARS,
) -> str:
    """Build the legacy one-line preview from already-sanitized evidence."""

    if (
        isinstance(maximum_chars, bool)
        or not isinstance(maximum_chars, int)
        or not 32 <= maximum_chars <= MAX_RECEIPT_PREVIEW_CHARS
    ):
        raise ReceiptSummaryError(
            f"maximum_chars must be between 32 and "
            f"{MAX_RECEIPT_PREVIEW_CHARS}"
        )
    for label, value in (
        ("stdout_bytes", stdout_bytes),
        ("stderr_bytes", stderr_bytes),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ReceiptSummaryError(f"{label} must be a non-negative integer")

    preview = (
        f"exit={exit_code if exit_code is not None else 'unknown'}; "
        f"stdout_bytes={stdout_bytes}; stderr_bytes={stderr_bytes}"
    )
    for stream, evidence in (
        ("stdout", stdout_evidence),
        ("stderr", stderr_evidence),
    ):
        if not isinstance(evidence, Mapping):
            continue
        for sample_name in ("head", "tail"):
            sample = evidence.get(sample_name)
            if not isinstance(sample, Mapping):
                continue
            text = sample.get("text")
            if not isinstance(text, str):
                continue
            line = next(
                (
                    part.strip()
                    for part in text.splitlines()
                    if part.strip()
                ),
                "",
            )
            if line:
                preview += f"; {stream}={line}"
                return preview[:maximum_chars]
    return preview[:maximum_chars]


__all__ = [
    "MAX_RECEIPT_PREVIEW_CHARS",
    "MAX_RECEIPT_SAMPLE_BYTES",
    "MAX_RECEIPT_STRUCTURE_JSON_BYTES",
    "MAX_RECEIPT_STREAM_EVIDENCE_BYTES",
    "RECEIPT_SAMPLE_BYTES",
    "ReceiptSummaryError",
    "build_receipt_preview",
    "summarize_stream_snapshot",
]
