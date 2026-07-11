#!/usr/bin/env python3
"""Normalize an already-built setuptools sdist for reproducible release hashes.

Setuptools emits current-time tar metadata even when ``SOURCE_DATE_EPOCH`` is
set. This packaging-only post-processing step retains every archive member and
its payload while normalizing tar ownership/timestamps and the gzip header.
"""

from __future__ import annotations

import argparse
import gzip
import io
import os
from pathlib import Path
import tarfile


def _source_date_epoch() -> int:
    value = os.environ.get("SOURCE_DATE_EPOCH", "0")
    try:
        epoch = int(value)
    except ValueError as exc:
        raise SystemExit(f"SOURCE_DATE_EPOCH must be an integer, got {value!r}") from exc
    if epoch < 0:
        raise SystemExit("SOURCE_DATE_EPOCH must be non-negative")
    return epoch


def normalize_sdist(path: Path, *, epoch: int) -> None:
    """Rewrite ``path`` with deterministic gzip and tar metadata."""
    with tarfile.open(path, mode="r:gz") as source:
        entries = [
            (member, source.extractfile(member).read() if member.isfile() else None)
            for member in source.getmembers()
        ]

    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT) as output:
                for member, payload in entries:
                    normalized = tarfile.TarInfo(member.name)
                    normalized.type = member.type
                    normalized.mode = member.mode
                    normalized.uid = normalized.gid = 0
                    normalized.uname = normalized.gname = ""
                    normalized.mtime = epoch
                    normalized.linkname = member.linkname
                    normalized.devmajor = member.devmajor
                    normalized.devminor = member.devminor
                    normalized.size = len(payload) if payload is not None else 0
                    output.addfile(normalized, io.BytesIO(payload) if payload is not None else None)
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser(description="normalize a setuptools sdist archive")
    parser.add_argument("sdist", type=Path)
    args = parser.parse_args()
    if not args.sdist.is_file():
        parser.error(f"sdist does not exist: {args.sdist}")
    normalize_sdist(args.sdist, epoch=_source_date_epoch())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
