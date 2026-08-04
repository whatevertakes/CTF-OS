"""Value-free summaries for generic managed Web response evidence.

The image-owned HTTP helper retains complete response bodies below ``/work``.
Those files are intentionally not copied into model context.  This module
accepts only small, canonical summary records from the immutable stdout
snapshot, so a remote Web action cannot turn an HTTP exit status into semantic
evidence while leaving its actual body observation ephemeral.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ctf_os.sandbox.files import (
    DEFAULT_STREAM_CAPTURE_MAX_BYTES,
    SafeFileError,
    read_bounded_regular,
)
from ctf_os.store.atomic import (
    StrictJSONError,
    canonical_json_record,
    strict_json_loads,
)

WEB_RESPONSE_SUMMARY_PREFIX = b"CTFOS_WEB_RESPONSE_V1 "
WEB_RESPONSE_SUMMARY_SCHEMA_VERSION = 1
MAX_WEB_RESPONSE_SUMMARY_LINE_BYTES = 8 * 1024
MAX_WEB_RESPONSE_SUMMARY_RECORDS = 16
MAX_WEB_RESPONSE_OBSERVATIONS = 16
MAX_WEB_RESPONSE_SAVED_BYTES = 256 * 1024 * 1024
MAX_WEB_RESPONSE_REPORTED_MATCH_COUNT = 1_000_000

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RECORD_KEYS = {
    "body_sha256",
    "kind",
    "observations",
    "request_sha256",
    "saved_bytes",
    "schema_version",
    "status",
    "truncated",
}
_OBSERVATION_KEYS = {
    "count_capped",
    "match_count",
    "needle_sha256",
    "present",
}


class WebResponseSummaryError(ValueError):
    """One remote Web action lacks a complete canonical body summary."""

    def __init__(self, reason_code: str, message: str) -> None:
        self.reason_code = reason_code
        super().__init__(message)


def _integer(value: object, *, minimum: int, maximum: int) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, int)
        and minimum <= value <= maximum
    )


def _validate_observation(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != _OBSERVATION_KEYS:
        raise WebResponseSummaryError(
            "observation_schema_invalid",
            "Web response observation has an invalid schema",
        )
    needle_sha256 = value.get("needle_sha256")
    present = value.get("present")
    match_count = value.get("match_count")
    count_capped = value.get("count_capped")
    if not isinstance(needle_sha256, str) or not _SHA256.fullmatch(
        needle_sha256
    ):
        raise WebResponseSummaryError(
            "observation_digest_invalid",
            "Web response observation needle digest is invalid",
        )
    if not isinstance(present, bool) or not isinstance(count_capped, bool):
        raise WebResponseSummaryError(
            "observation_boolean_invalid",
            "Web response observation booleans are invalid",
        )
    if not _integer(
        match_count,
        minimum=0,
        maximum=MAX_WEB_RESPONSE_REPORTED_MATCH_COUNT,
    ):
        raise WebResponseSummaryError(
            "observation_count_invalid",
            "Web response observation match count is invalid",
        )
    assert isinstance(match_count, int)
    if present is not (match_count > 0):
        raise WebResponseSummaryError(
            "observation_presence_inconsistent",
            "Web response observation presence and count disagree",
        )
    if count_capped and match_count != MAX_WEB_RESPONSE_REPORTED_MATCH_COUNT:
        raise WebResponseSummaryError(
            "observation_cap_inconsistent",
            "Capped Web response observation has a non-cap count",
        )
    return {
        "count_capped": count_capped,
        "match_count": match_count,
        "needle_sha256": needle_sha256,
        "present": present,
    }


def _validate_record(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != _RECORD_KEYS:
        raise WebResponseSummaryError(
            "record_schema_invalid",
            "Web response summary has an invalid schema",
        )
    if (
        value.get("schema_version")
        != WEB_RESPONSE_SUMMARY_SCHEMA_VERSION
        or value.get("kind") != "ctfos_web_response"
    ):
        raise WebResponseSummaryError(
            "record_protocol_invalid",
            "Web response summary protocol is unsupported",
        )
    for field in ("request_sha256", "body_sha256"):
        digest = value.get(field)
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise WebResponseSummaryError(
                "record_digest_invalid",
                f"Web response summary {field} is invalid",
            )
    if not _integer(value.get("status"), minimum=100, maximum=599):
        raise WebResponseSummaryError(
            "record_status_invalid",
            "Web response summary HTTP status is invalid",
        )
    if not _integer(
        value.get("saved_bytes"),
        minimum=0,
        maximum=MAX_WEB_RESPONSE_SAVED_BYTES,
    ):
        raise WebResponseSummaryError(
            "record_size_invalid",
            "Web response summary byte count is invalid",
        )
    if not isinstance(value.get("truncated"), bool):
        raise WebResponseSummaryError(
            "record_truncation_invalid",
            "Web response summary truncation bit is invalid",
        )
    observations = value.get("observations")
    if (
        not isinstance(observations, list)
        or len(observations) > MAX_WEB_RESPONSE_OBSERVATIONS
    ):
        raise WebResponseSummaryError(
            "observation_set_invalid",
            "Web response summary observation set is invalid",
        )
    normalized_observations = [
        _validate_observation(item) for item in observations
    ]
    needle_digests = [
        str(item["needle_sha256"]) for item in normalized_observations
    ]
    if len(set(needle_digests)) != len(needle_digests):
        raise WebResponseSummaryError(
            "observation_digest_duplicate",
            "Web response summary repeats an observation digest",
        )
    return {
        "body_sha256": value["body_sha256"],
        "kind": "ctfos_web_response",
        "observations": normalized_observations,
        "request_sha256": value["request_sha256"],
        "saved_bytes": value["saved_bytes"],
        "schema_version": WEB_RESPONSE_SUMMARY_SCHEMA_VERSION,
        "status": value["status"],
        "truncated": value["truncated"],
    }


def parse_web_response_summaries(payload: bytes) -> tuple[dict[str, object], ...]:
    """Parse every canonical physical summary line from complete stdout."""

    records: list[dict[str, object]] = []
    for line in payload.splitlines():
        if not line.startswith(WEB_RESPONSE_SUMMARY_PREFIX):
            continue
        if len(line) > MAX_WEB_RESPONSE_SUMMARY_LINE_BYTES:
            raise WebResponseSummaryError(
                "record_line_oversized",
                "Web response summary line exceeds its bound",
            )
        if len(records) == MAX_WEB_RESPONSE_SUMMARY_RECORDS:
            raise WebResponseSummaryError(
                "record_set_oversized",
                "Web response summary record count exceeds its bound",
            )
        encoded = line[len(WEB_RESPONSE_SUMMARY_PREFIX) :]
        try:
            decoded = strict_json_loads(
                encoded,
                max_bytes=MAX_WEB_RESPONSE_SUMMARY_LINE_BYTES,
                max_depth=8,
            )
        except StrictJSONError as error:
            raise WebResponseSummaryError(
                "record_json_invalid",
                "Web response summary is not strict JSON",
            ) from error
        record = _validate_record(decoded)
        expected_line = WEB_RESPONSE_SUMMARY_PREFIX + canonical_json_record(
            record
        ).encode("ascii")
        if line != expected_line:
            raise WebResponseSummaryError(
                "record_not_canonical",
                "Web response summary JSON is not canonical",
            )
        records.append(record)
    if not records:
        raise WebResponseSummaryError(
            "record_missing",
            "managed remote Web stdout has no response summary record",
        )
    return tuple(records)


def evaluate_web_response_stdout(
    root: Path,
    locator: str,
    *,
    expected_sha256: str,
    expected_size: int,
    coverage: object,
) -> dict[str, Any]:
    """Return a bounded pass/fail projection for one immutable stdout."""

    if coverage != "complete_stream":
        return {
            "schema_version": WEB_RESPONSE_SUMMARY_SCHEMA_VERSION,
            "valid": False,
            "reason_code": "stdout_incomplete",
            "record_count": 0,
            "records": [],
        }
    try:
        payload = read_bounded_regular(
            root,
            locator,
            maximum_bytes=DEFAULT_STREAM_CAPTURE_MAX_BYTES,
            expected_sha256=expected_sha256,
            expected_size=expected_size,
        )
        records = parse_web_response_summaries(payload)
    except WebResponseSummaryError as error:
        return {
            "schema_version": WEB_RESPONSE_SUMMARY_SCHEMA_VERSION,
            "valid": False,
            "reason_code": error.reason_code,
            "record_count": 0,
            "records": [],
        }
    except (OSError, SafeFileError, ValueError):
        return {
            "schema_version": WEB_RESPONSE_SUMMARY_SCHEMA_VERSION,
            "valid": False,
            "reason_code": "stdout_binding_invalid",
            "record_count": 0,
            "records": [],
        }
    return {
        "schema_version": WEB_RESPONSE_SUMMARY_SCHEMA_VERSION,
        "valid": True,
        "reason_code": "accepted",
        "record_count": len(records),
        "records": list(records),
    }


__all__ = [
    "MAX_WEB_RESPONSE_OBSERVATIONS",
    "MAX_WEB_RESPONSE_REPORTED_MATCH_COUNT",
    "MAX_WEB_RESPONSE_SUMMARY_LINE_BYTES",
    "MAX_WEB_RESPONSE_SUMMARY_RECORDS",
    "WEB_RESPONSE_SUMMARY_PREFIX",
    "WEB_RESPONSE_SUMMARY_SCHEMA_VERSION",
    "WebResponseSummaryError",
    "evaluate_web_response_stdout",
    "parse_web_response_summaries",
]
