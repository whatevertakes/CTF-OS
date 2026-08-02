#!/usr/bin/env python3
"""Functional regressions for the bounded browser history timeline template."""

from __future__ import annotations

import hashlib
import json
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
from datetime import UTC, datetime


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "templates" / "forensic" / "browser_timeline.py"


def invoke(*arguments: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *(str(value) for value in arguments)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )


def webkit_microseconds(value: datetime) -> int:
    return int((value - datetime(1601, 1, 1, tzinfo=UTC)).total_seconds() * 1_000_000)


no_args = invoke()
assert no_args.returncode == 2, no_args
assert "usage:" in no_args.stderr.casefold(), no_args.stderr

with tempfile.TemporaryDirectory(prefix="ctf-browser-timeline-") as directory:
    root = pathlib.Path(directory)
    work = root / "work"
    work.mkdir()

    chromium = root / "History"
    connection = sqlite3.connect(chromium)
    connection.executescript(
        """
        CREATE TABLE urls(
          id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR,
          visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER
        );
        CREATE TABLE visits(
          id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER,
          from_visit INTEGER, transition INTEGER
        );
        """
    )
    first_time = webkit_microseconds(datetime(2025, 1, 2, 3, 4, 5, tzinfo=UTC))
    connection.execute(
        "INSERT INTO urls VALUES(1,?,?,?,?,?)",
        ("https://example.test/one", "One", 1, 0, first_time),
    )
    connection.execute(
        "INSERT INTO visits VALUES(1,1,?,0,805306368)",
        (first_time,),
    )
    connection.execute(
        "INSERT INTO urls VALUES(2,?,?,?,?,?)",
        ("https://example.test/two", "Two", 1, 0, first_time + 1),
    )
    connection.execute(
        "INSERT INTO visits VALUES(2,2,?,1,1)",
        (first_time + 1,),
    )
    connection.execute(
        "INSERT INTO urls VALUES(3,?,?,?,?,?)",
        (sqlite3.Binary(b"\xff"), "T" * 70_000, 1, 0, float("inf")),
    )
    connection.execute(
        "INSERT INTO visits VALUES(3,3,?,?,?)",
        (
            float("inf"),
            sqlite3.Binary(b"\xff"),
            sqlite3.Binary(b"\x00\xff"),
        ),
    )
    connection.commit()
    connection.close()
    (root / "History-wal").write_bytes(b"bounded test marker")

    before = chromium.stat()
    before_hash = hashlib.sha256(chromium.read_bytes()).hexdigest()
    output_dir = work / "chromium"
    result = invoke(chromium, "--output-dir", output_dir)
    assert result.returncode == 0, result
    summary = json.loads(result.stdout)
    assert summary == {
        "artifact": str(output_dir / "browser-timeline.json"),
        "browser": "chromium",
        "row_count": 3,
        "truncated": False,
    }, summary
    timeline = json.loads((output_dir / "browser-timeline.json").read_text())
    assert timeline["browser"] == "chromium", timeline
    assert timeline["source"] == {
        "basename": "History",
        "size_bytes": chromium.stat().st_size,
        "wal_sidecar_ignored": True,
    }, timeline
    assert timeline["records"][0]["visited_at_utc"] == "2025-01-02T03:04:05Z"
    assert timeline["records"][0]["url"] == "https://example.test/one"
    assert timeline["records"][1]["from_visit"] == 1
    hostile = timeline["records"][2]
    assert hostile["source_timestamp_us"] == {
        "type": "non_finite_float",
        "value": "+infinity",
    }, hostile
    assert hostile["visited_at_utc"] is None, hostile
    assert hostile["from_visit"] == {
        "base64": "/w==",
        "original_bytes": 1,
        "truncated": False,
        "type": "blob",
    }, hostile
    assert hostile["transition"] == {
        "base64": "AP8=",
        "original_bytes": 2,
        "truncated": False,
        "type": "blob",
    }, hostile
    assert hostile["url"] == "\ufffd", hostile
    assert len(hostile["title"].encode("utf-8")) == 64 * 1024, hostile
    after = chromium.stat()
    assert (before.st_size, before.st_mtime_ns, before_hash) == (
        after.st_size,
        after.st_mtime_ns,
        hashlib.sha256(chromium.read_bytes()).hexdigest(),
    )

    limited_dir = work / "limited"
    limited = invoke(
        chromium,
        "--max-rows",
        1,
        "--output-dir",
        limited_dir,
    )
    assert limited.returncode == 0, limited
    limited_payload = json.loads(
        (limited_dir / "browser-timeline.json").read_text()
    )
    assert limited_payload["row_count"] == 1, limited_payload
    assert limited_payload["truncated"] is True, limited_payload
    assert limited_payload["truncation_reason"] == "row_limit", limited_payload

    firefox = root / "places.sqlite"
    connection = sqlite3.connect(firefox)
    connection.executescript(
        """
        CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url LONGVARCHAR, title LONGVARCHAR);
        CREATE TABLE moz_historyvisits(
          id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER,
          visit_date INTEGER, visit_type INTEGER
        );
        INSERT INTO moz_places VALUES(7,'https://mozilla.test/','Mozilla');
        INSERT INTO moz_historyvisits VALUES(9,0,7,1735787045000000,1);
        """
    )
    connection.commit()
    connection.close()
    firefox_dir = work / "firefox"
    firefox_result = invoke(
        firefox,
        "--browser",
        "firefox",
        "--output-dir",
        firefox_dir,
    )
    assert firefox_result.returncode == 0, firefox_result
    firefox_payload = json.loads(
        (firefox_dir / "browser-timeline.json").read_text()
    )
    assert firefox_payload["records"] == [
        {
            "browser": "firefox",
            "from_visit": 0,
            "source_timestamp_us": 1735787045000000,
            "title": "Mozilla",
            "transition": 1,
            "url": "https://mozilla.test/",
            "visit_id": 9,
            "visited_at_utc": "2025-01-02T03:04:05Z",
        }
    ], firefox_payload

    wrong_schema = invoke(
        firefox,
        "--browser",
        "chromium",
        "--output-dir",
        work / "wrong",
    )
    assert wrong_schema.returncode == 1, wrong_schema
    assert "requested chromium schema" in wrong_schema.stderr, wrong_schema.stderr

    symlink = root / "linked.sqlite"
    symlink.symlink_to(firefox)
    linked = invoke(symlink, "--output-dir", work / "linked")
    assert linked.returncode == 1, linked
    assert "not a symlink" in linked.stderr, linked.stderr

    outside = root / "outside"
    outside.write_text("do not overwrite", encoding="utf-8")
    attacked_dir = work / "attacked"
    attacked_dir.mkdir()
    (attacked_dir / "browser-timeline.json").symlink_to(outside)
    attacked = invoke(firefox, "--output-dir", attacked_dir)
    assert attacked.returncode == 1, attacked
    assert outside.read_text(encoding="utf-8") == "do not overwrite"

print("forensic browser timeline regressions: ok")
