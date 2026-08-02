#!/usr/bin/env python3
"""Extract a bounded UTC timeline from Chromium or Firefox history SQLite."""

from __future__ import annotations

import argparse
import base64
import json
import math
import os
import sqlite3
import stat
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote


TEMPLATE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TEMPLATE_ROOT / "rev"))
from safe_output import atomic_write, open_output_dir, remove_regular_output  # noqa: E402


ARTIFACT_NAME = "browser-timeline.json"
MAX_DATABASE_BYTES = 16 * 1024 * 1024 * 1024
MAX_ROWS = 5000
MAX_TEXT_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_SQLITE_VALUE_BYTES = 1024 * 1024
QUERY_TIMEOUT_SECONDS = 10.0


class TimelineError(RuntimeError):
    pass


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="browser_timeline.py",
        description="Write a bounded Chromium/Firefox visit timeline under /work.",
    )
    parser.add_argument("database")
    parser.add_argument(
        "--browser",
        choices=("auto", "chromium", "firefox"),
        default="auto",
    )
    parser.add_argument("--max-rows", type=int, default=1000)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("/work/forensic"),
    )
    return parser


def _open_database(path: str) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise TimelineError("database must be a readable regular file, not a symlink") from exc
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        raise TimelineError("database must be a regular file")
    if metadata.st_size > MAX_DATABASE_BYTES:
        os.close(descriptor)
        raise TimelineError("database exceeds the input byte limit")
    return descriptor


def _authorizer(
    action: int,
    argument_one: str | None,
    argument_two: str | None,
    database_name: str | None,
    trigger_name: str | None,
) -> int:
    del argument_one, argument_two, database_name, trigger_name
    allowed = {
        sqlite3.SQLITE_FUNCTION,
        sqlite3.SQLITE_READ,
        sqlite3.SQLITE_SELECT,
    }
    return sqlite3.SQLITE_OK if action in allowed else sqlite3.SQLITE_DENY


def _has_table(connection: sqlite3.Connection, name: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_schema "
        "WHERE type='table' AND name=? COLLATE NOCASE LIMIT 1",
        (name,),
    ).fetchone()
    return row is not None


def _browser_kind(connection: sqlite3.Connection, requested: str) -> str:
    chromium = _has_table(connection, "urls") and _has_table(connection, "visits")
    firefox = _has_table(connection, "moz_places") and _has_table(
        connection,
        "moz_historyvisits",
    )
    if requested == "chromium" and chromium:
        return requested
    if requested == "firefox" and firefox:
        return requested
    if requested != "auto":
        raise TimelineError(f"database does not contain the requested {requested} schema")
    if chromium and not firefox:
        return "chromium"
    if firefox and not chromium:
        return "firefox"
    if chromium and firefox:
        raise TimelineError("database contains both browser schemas; select --browser")
    raise TimelineError("unsupported browser history schema")


def _bounded_text(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        decoded = value.decode("utf-8", errors="replace")
    else:
        decoded = str(value)
    encoded = decoded.encode("utf-8")
    if len(encoded) <= MAX_TEXT_BYTES:
        return decoded
    bounded = encoded[:MAX_TEXT_BYTES]
    return bounded.decode("utf-8", errors="ignore")


def _json_scalar(value: object) -> object:
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if math.isfinite(value):
            return value
        if math.isnan(value):
            label = "nan"
        elif value > 0:
            label = "+infinity"
        else:
            label = "-infinity"
        return {"type": "non_finite_float", "value": label}
    if isinstance(value, bytes):
        bounded = value[:MAX_TEXT_BYTES]
        return {
            "base64": base64.b64encode(bounded).decode("ascii"),
            "original_bytes": len(value),
            "truncated": len(value) > len(bounded),
            "type": "blob",
        }
    return _bounded_text(value)


def _utc_from_microseconds(value: object, *, browser: str) -> str | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        if browser == "chromium":
            timestamp = datetime(1601, 1, 1, tzinfo=UTC) + timedelta(
                microseconds=value
            )
        else:
            timestamp = datetime.fromtimestamp(value / 1_000_000, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None
    return timestamp.isoformat().replace("+00:00", "Z")


def _query_rows(
    connection: sqlite3.Connection,
    browser: str,
    maximum_rows: int,
) -> tuple[list[dict[str, Any]], bool, str | None]:
    if browser == "chromium":
        query = (
            "SELECT visits.id,urls.url,urls.title,visits.visit_time,"
            "visits.from_visit,visits.transition "
            "FROM visits JOIN urls ON urls.id=visits.url "
            "ORDER BY visits.visit_time,visits.id LIMIT ?"
        )
    else:
        query = (
            "SELECT moz_historyvisits.id,moz_places.url,moz_places.title,"
            "moz_historyvisits.visit_date,moz_historyvisits.from_visit,"
            "moz_historyvisits.visit_type "
            "FROM moz_historyvisits JOIN moz_places "
            "ON moz_places.id=moz_historyvisits.place_id "
            "ORDER BY moz_historyvisits.visit_date,moz_historyvisits.id LIMIT ?"
        )
    cursor = connection.execute(query, (maximum_rows + 1,))
    records: list[dict[str, Any]] = []
    encoded_record_bytes = 0
    truncated = False
    reason: str | None = None
    for row in cursor:
        if len(records) >= maximum_rows:
            truncated = True
            reason = "row_limit"
            break
        source_timestamp = row[3]
        record = {
            "browser": browser,
            "from_visit": _json_scalar(row[4]),
            "source_timestamp_us": _json_scalar(source_timestamp),
            "title": _bounded_text(row[2]),
            "transition": _json_scalar(row[5]),
            "url": _bounded_text(row[1]),
            "visit_id": _json_scalar(row[0]),
            "visited_at_utc": _utc_from_microseconds(
                source_timestamp,
                browser=browser,
            ),
        }
        encoded = json.dumps(
            record,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        if encoded_record_bytes + len(encoded) > MAX_OUTPUT_BYTES - 16 * 1024:
            truncated = True
            reason = "output_limit"
            break
        records.append(record)
        encoded_record_bytes += len(encoded)
    return records, truncated, reason


def _wal_sidecar_present(database: Path) -> bool:
    sidecar = Path(f"{database}-wal")
    try:
        metadata = sidecar.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode)


def _extract(arguments: argparse.Namespace) -> dict[str, Any]:
    if not 1 <= arguments.max_rows <= MAX_ROWS:
        raise TimelineError(f"--max-rows must be between 1 and {MAX_ROWS}")
    descriptor = _open_database(arguments.database)
    connection: sqlite3.Connection | None = None
    try:
        descriptor_path = f"/proc/self/fd/{descriptor}"
        uri = f"file:{quote(descriptor_path, safe='/')}?mode=ro&immutable=1"
        connection = sqlite3.connect(uri, uri=True, timeout=0.0)
        connection.execute("PRAGMA query_only=ON")
        connection.enable_load_extension(False)
        if hasattr(connection, "setlimit"):
            connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MAX_SQLITE_VALUE_BYTES)
            connection.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 64 * 1024)
            connection.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, 64)
            connection.setlimit(sqlite3.SQLITE_LIMIT_COMPOUND_SELECT, 16)
        deadline = time.monotonic() + QUERY_TIMEOUT_SECONDS
        connection.set_progress_handler(
            lambda: 1 if time.monotonic() >= deadline else 0,
            1000,
        )
        connection.set_authorizer(_authorizer)
        browser = _browser_kind(connection, arguments.browser)
        records, truncated, reason = _query_rows(
            connection,
            browser,
            arguments.max_rows,
        )
        result: dict[str, Any] = {
            "browser": browser,
            "records": records,
            "row_count": len(records),
            "schema_version": 1,
            "source": {
                "basename": Path(arguments.database).name,
                "size_bytes": os.fstat(descriptor).st_size,
                "wal_sidecar_ignored": _wal_sidecar_present(Path(arguments.database)),
            },
            "truncated": truncated,
        }
        if reason is not None:
            result["truncation_reason"] = reason
        return result
    except sqlite3.DatabaseError as exc:
        raise TimelineError("browser history query failed") from exc
    finally:
        if connection is not None:
            connection.close()
        os.close(descriptor)


def main() -> int:
    parser = _parser()
    if len(sys.argv) == 1:
        parser.print_usage(sys.stderr)
        return 2
    arguments = parser.parse_args()
    output_descriptor: int | None = None
    try:
        output_descriptor = open_output_dir(arguments.output_dir)
        remove_regular_output(output_descriptor, ARTIFACT_NAME)
        result = _extract(arguments)
        encoded = json.dumps(
            result,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        if len(encoded) > MAX_OUTPUT_BYTES:
            raise TimelineError("timeline exceeds the output byte limit")
        atomic_write(output_descriptor, ARTIFACT_NAME, encoded + b"\n")
        print(
            json.dumps(
                {
                    "artifact": str(arguments.output_dir / ARTIFACT_NAME),
                    "browser": result["browser"],
                    "row_count": result["row_count"],
                    "truncated": result["truncated"],
                },
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    except TimelineError as exc:
        print(f"browser_timeline.py: {exc}", file=sys.stderr)
        return 1
    except (OSError, TypeError, ValueError):
        print("browser_timeline.py: extraction failed safely", file=sys.stderr)
        return 1
    finally:
        if output_descriptor is not None:
            os.close(output_descriptor)


if __name__ == "__main__":
    raise SystemExit(main())
