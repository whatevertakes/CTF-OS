#!/usr/bin/env python3
"""Functional safety regressions for ctf-sqlite-readonly."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
import time


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
READER = REPO_ROOT / "scripts" / "ctf-sqlite-readonly"
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_DATABASE_BYTES = 16 * 1024 * 1024 * 1024


def invoke(*arguments: object, timeout: float = 5.0) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(READER), *(str(value) for value in arguments)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout,
    )


def payload(result: subprocess.CompletedProcess[bytes]) -> dict[str, object]:
    assert len(result.stdout) <= MAX_OUTPUT_BYTES + 1, len(result.stdout)
    parsed = json.loads(result.stdout.decode("utf-8"))
    assert isinstance(parsed, dict), parsed
    return parsed


no_args = invoke()
assert no_args.returncode == 2, no_args
assert b"usage:" in no_args.stderr.lower(), no_args.stderr

self_test = invoke("--self-test")
assert self_test.returncode == 0, self_test
assert self_test.stdout == b"", self_test.stdout

with tempfile.TemporaryDirectory(prefix="ctf-sqlite-readonly-") as directory:
    root = pathlib.Path(directory)
    database = root / "evidence.sqlite"
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE events(id INTEGER PRIMARY KEY, label TEXT, payload BLOB, score REAL);
        INSERT INTO events(label,payload,score) VALUES('alpha',X'0001ff',1.5);
        INSERT INTO events(label,payload,score) VALUES('beta',X'80',1e999);
        INSERT INTO events(label,payload,score) VALUES(CAST(X'80' AS TEXT),X'',-1e999);
        """
    )
    connection.commit()
    connection.close()

    before = database.stat()
    before_hash = hashlib.sha256(database.read_bytes()).hexdigest()

    selected = invoke(database, "SELECT id,label FROM events ORDER BY id")
    assert selected.returncode == 0, selected
    selected_payload = payload(selected)
    assert selected_payload == {
        "columns": ["id", "label"],
        "ok": True,
        "row_count": 3,
        "rows": [
            [1, "alpha"],
            [2, "beta"],
            [
                3,
                {
                    "base64": "gA==",
                    "original_bytes": 1,
                    "truncated": False,
                    "type": "invalid_utf8_text",
                },
            ],
        ],
        "truncated": False,
    }, selected_payload

    schema = invoke(database, "--schema")
    assert schema.returncode == 0, schema
    schema_payload = payload(schema)
    assert schema_payload["ok"] is True, schema_payload
    assert schema_payload["columns"] == ["type", "name", "tbl_name", "sql"]
    assert any(row[1] == "events" for row in schema_payload["rows"])

    types = invoke(database, "SELECT payload,score FROM events ORDER BY id")
    assert types.returncode == 0, types
    types_payload = payload(types)
    assert types_payload["rows"][0][0] == {
        "base64": "AAH/",
        "original_bytes": 3,
        "truncated": False,
        "type": "blob",
    }
    assert types_payload["rows"][1][1] == {
        "type": "non_finite_float",
        "value": "+infinity",
    }
    assert types_payload["rows"][2][1] == {
        "type": "non_finite_float",
        "value": "-infinity",
    }

    row_limited = invoke(database, "SELECT id FROM events ORDER BY id", "--max-rows", 2)
    assert row_limited.returncode == 0, row_limited
    row_payload = payload(row_limited)
    assert row_payload["row_count"] == 2, row_payload
    assert row_payload["truncated"] is True, row_payload
    assert row_payload["truncation_reason"] == "row_limit", row_payload

    output_limited = invoke(
        database,
        "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<200) "
        "SELECT hex(zeroblob(70000)) FROM n",
        "--max-rows",
        1000,
        timeout=10,
    )
    assert output_limited.returncode == 0, output_limited
    output_payload = payload(output_limited)
    assert output_payload["truncated"] is True, output_payload
    assert output_payload["truncation_reason"] == "output_limit", output_payload

    attached = root / "must-not-exist.sqlite"
    denied_queries = (
        "INSERT INTO events(label) VALUES('blocked')",
        "CREATE TABLE blocked(value)",
        "PRAGMA journal_mode=WAL",
        f"ATTACH DATABASE '{attached}' AS other",
        "DETACH DATABASE main",
        "SELECT load_extension('/tmp/SENSITIVE_MARKER')",
        "SELECT 1; SELECT 2 /* SENSITIVE_MARKER */",
    )
    for query in denied_queries:
        denied = invoke(database, query)
        assert denied.returncode == 1, (query, denied)
        denied_payload = payload(denied)
        assert denied_payload["ok"] is False, (query, denied_payload)
        assert b"SENSITIVE_MARKER" not in denied.stdout + denied.stderr
    assert not attached.exists(), attached

    started = time.monotonic()
    recursive = invoke(
        database,
        "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n) "
        "SELECT max(x) FROM n",
        "--timeout",
        0.05,
        timeout=2,
    )
    elapsed = time.monotonic() - started
    assert recursive.returncode == 1, recursive
    assert payload(recursive)["error"] == "query_timeout", recursive.stdout
    assert elapsed < 1.5, elapsed

    after = database.stat()
    after_hash = hashlib.sha256(database.read_bytes()).hexdigest()
    assert (before.st_size, before.st_mtime_ns, before_hash) == (
        after.st_size,
        after.st_mtime_ns,
        after_hash,
    )
    verify = sqlite3.connect(database)
    assert verify.execute("SELECT count(*) FROM events").fetchone() == (3,)
    verify.close()

    symlink = root / "symlink.sqlite"
    symlink.symlink_to(database)
    rejected_symlink = invoke(symlink, "SELECT 1")
    assert rejected_symlink.returncode == 1, rejected_symlink
    assert payload(rejected_symlink)["error"] == "invalid_database"

    fifo = root / "database.fifo"
    os.mkfifo(fifo)
    rejected_fifo = invoke(fifo, "SELECT 1")
    assert rejected_fifo.returncode == 1, rejected_fifo
    assert payload(rejected_fifo)["error"] == "invalid_database"

    oversized = root / "oversized.sqlite"
    with oversized.open("wb") as handle:
        handle.truncate(MAX_DATABASE_BYTES + 1)
    rejected_oversized = invoke(oversized, "SELECT 1")
    assert rejected_oversized.returncode == 1, rejected_oversized
    assert payload(rejected_oversized)["error"] == "database_too_large"

    corrupt = root / "corrupt.sqlite"
    corrupt.write_bytes(b"not a sqlite database")
    rejected_corrupt = invoke(corrupt, "SELECT * FROM sqlite_schema")
    assert rejected_corrupt.returncode == 1, rejected_corrupt
    assert payload(rejected_corrupt)["error"] == "query_failed"

print("ctf-sqlite-readonly functional safety regressions: ok")
