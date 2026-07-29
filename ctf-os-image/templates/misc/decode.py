#!/usr/bin/env python3
"""Bounded recursive decoder for common misc challenge encodings."""

from __future__ import annotations

import argparse
import base64
import binascii
import codecs
import hashlib
import json
import os
import re
import stat
import sys
import urllib.parse
import zlib
from collections import deque
from pathlib import Path
from typing import Callable, Iterator

from safe_output import atomic_write, open_output_dir

OUTPUT_DIR = Path("/work/misc")
FLAG_RE_BYTES = re.compile(rb"[A-Za-z0-9_]{2,20}\{[^}\r\n]{1,200}\}")
HEX_RE = re.compile(rb"(?:0x)?[0-9a-fA-F]{2}(?:[\s:]?[0-9a-fA-F]{2})+")
BASE64_RE = re.compile(rb"[A-Za-z0-9+/_-]+={0,2}")
URL_ESCAPE_RE = re.compile(r"%[0-9a-fA-F]{2}")
DEFAULT_MAX_TOTAL_BYTES = 64 * 1024 * 1024
HARD_MAX_TOTAL_BYTES = 1024 * 1024 * 1024


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Try bounded hex/base64/URL/ROT13/compression layers under /work/misc."
    )
    parser.add_argument("input", type=Path, help="input file, normally under /challenge")
    parser.add_argument("--depth", type=int, default=3, help="maximum transform depth")
    parser.add_argument("--nodes", type=int, default=128, help="maximum decoded nodes")
    parser.add_argument(
        "--max-bytes", type=int, default=16 * 1024 * 1024, help="maximum bytes per decoded node"
    )
    parser.add_argument(
        "--max-total-bytes",
        type=int,
        default=DEFAULT_MAX_TOTAL_BYTES,
        help="hard cap on cumulative queued/processed node bytes (default: 64 MiB)",
    )
    parser.add_argument(
        "--max-flags-per-node",
        type=int,
        default=256,
        help="maximum flag matches retained per node (default: 256, max: 1000)",
    )
    parser.add_argument(
        "--max-flags-total",
        type=int,
        default=1000,
        help="maximum flag matches retained overall (default: 1000, max: 10000)",
    )
    args = parser.parse_args()
    if not args.input.is_file():
        parser.error(f"input file does not exist: {args.input}")
    if not 0 <= args.depth <= 8:
        parser.error("--depth must be between 0 and 8")
    if not 1 <= args.nodes <= 1024:
        parser.error("--nodes must be between 1 and 1024")
    if not 1 <= args.max_bytes <= 256 * 1024 * 1024:
        parser.error("--max-bytes must be between 1 byte and 256 MiB")
    if not args.max_bytes <= args.max_total_bytes <= HARD_MAX_TOTAL_BYTES:
        parser.error("--max-total-bytes must be >= --max-bytes and <= 1 GiB")
    if not 1 <= args.max_flags_per_node <= 1000:
        parser.error("--max-flags-per-node must be between 1 and 1000")
    if not 1 <= args.max_flags_total <= 10000:
        parser.error("--max-flags-total must be between 1 and 10000")
    return args


def best_text(data: bytes) -> tuple[str | None, str | None]:
    best: tuple[float, str, str] | None = None
    for encoding in ("utf-8", "cp949", "euc-kr"):
        try:
            text = data.decode(encoding)
        except UnicodeDecodeError:
            continue
        if not text:
            return "", encoding
        score = sum(char.isprintable() or char in "\r\n\t" for char in text) / len(text)
        candidate = (score, text, encoding)
        if best is None or candidate[0] > best[0]:
            best = candidate
    if best is None:
        return None, None
    return best[1], best[2]


def limited_decompress(data: bytes, wbits: int, limit: int) -> bytes | None:
    try:
        decoder = zlib.decompressobj(wbits)
        result = decoder.decompress(data, limit + 1)
        if len(result) > limit or decoder.unconsumed_tail:
            return None
        result += decoder.flush(limit + 1 - len(result))
        if not decoder.eof:
            return None
        return result if len(result) <= limit else None
    except zlib.error:
        return None


def transforms(
    data: bytes, node_limit: int, remaining: Callable[[], int]
) -> Iterator[tuple[str, bytes | None]]:
    stripped = b"".join(data.split())

    hex_candidate = stripped.replace(b":", b"")
    hex_payload = hex_candidate.removeprefix(b"0x")
    if HEX_RE.fullmatch(stripped) and len(hex_payload) % 2 == 0:
        decoded_size = len(hex_payload) // 2
        if decoded_size <= node_limit:
            if decoded_size > remaining():
                yield "hex", None
            else:
                try:
                    yield "hex", bytes.fromhex(hex_payload.decode("ascii"))
                except ValueError:
                    pass

    if len(stripped) >= 4 and BASE64_RE.fullmatch(stripped):
        padded = stripped + b"=" * ((-len(stripped)) % 4)
        estimated_size = (len(padded) // 4) * 3
        if estimated_size <= node_limit + 2:
            try:
                decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
                if decoded != data and len(decoded) <= node_limit:
                    yield ("base64", decoded) if len(decoded) <= remaining() else ("base64", None)
            except (ValueError, binascii.Error):
                pass

    text, encoding = best_text(data)
    if text is not None:
        if URL_ESCAPE_RE.search(text) and len(data) <= node_limit:
            decoded = urllib.parse.unquote_to_bytes(text)
            if decoded != data and len(decoded) <= node_limit:
                yield (
                    (f"url({encoding})", decoded)
                    if len(decoded) <= remaining()
                    else (f"url({encoding})", None)
                )
        if text.isascii() and any(char.isalpha() for char in text) and len(data) <= node_limit:
            rotated = codecs.decode(text, "rot_13").encode("ascii")
            if rotated != data:
                yield ("rot13", rotated) if len(rotated) <= remaining() else ("rot13", None)

    if data.startswith(b"\x1f\x8b"):
        decoded = limited_decompress(data, 16 + zlib.MAX_WBITS, node_limit)
        if decoded is not None:
            yield ("gzip", decoded) if len(decoded) <= remaining() else ("gzip", None)
    if len(data) >= 2 and data[0] == 0x78:
        decoded = limited_decompress(data, zlib.MAX_WBITS, node_limit)
        if decoded is not None:
            yield ("zlib", decoded) if len(decoded) <= remaining() else ("zlib", None)


def read_regular_bounded(path: Path, limit: int) -> bytearray:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(path, flags)
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode):
            raise OSError("input is not a regular file")
        if file_stat.st_size > limit:
            raise ValueError(f"input size {file_stat.st_size} exceeds {limit}")
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(descriptor, min(1024 * 1024, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > limit:
            raise ValueError(f"input grew beyond {limit} bytes")
        return data
    finally:
        os.close(descriptor)


def main() -> int:
    args = parse_args()
    try:
        source = bytes(read_regular_bounded(args.input, args.max_bytes))
    except (OSError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": "invalid-or-oversized-input",
                    "message": str(exc),
                    "max_bytes": args.max_bytes,
                }
            )
        )
        return 2

    queue: deque[tuple[int, list[str], bytes]] = deque([(0, ["input"], source)])
    source_digest = hashlib.sha256(source).hexdigest()
    discovered: set[str] = {source_digest}
    records: list[dict[str, object]] = []
    candidate_files: list[str] = []
    all_flags: set[str] = set()
    flag_results = 0
    flags_truncated = False
    queued_bytes = len(source)
    peak_queued_bytes = queued_bytes
    processed_bytes = 0
    total_enqueued_bytes = len(source)
    byte_budget_exhausted = False
    try:
        output_descriptor = open_output_dir(OUTPUT_DIR)
    except OSError as exc:
        print(
            json.dumps(
                {"ok": False, "error": "UnsafeOutputDirectory", "message": str(exc)}
            )
        )
        return 2

    while queue and len(records) < args.nodes:
        depth, path, data = queue.popleft()
        queued_bytes -= len(data)
        if processed_bytes + len(data) > args.max_total_bytes:
            byte_budget_exhausted = True
            break
        processed_bytes += len(data)
        digest = hashlib.sha256(data).hexdigest()
        text, encoding = best_text(data)
        flags: list[str] = []
        node_flags_truncated = False
        for match in FLAG_RE_BYTES.finditer(data):
            if (
                len(flags) >= args.max_flags_per_node
                or flag_results >= args.max_flags_total
            ):
                node_flags_truncated = True
                flags_truncated = True
                break
            flags.append(match.group(0).decode("utf-8", errors="replace"))
            flag_results += 1
        all_flags.update(flags)

        record: dict[str, object] = {
            "path": " -> ".join(path),
            "depth": depth,
            "size": len(data),
            "sha256": digest,
            "encoding": encoding,
            "text_preview": text[:500] if text is not None else None,
            "flags": flags,
            "flags_truncated": node_flags_truncated,
        }
        records.append(record)
        if flags and len(candidate_files) < 16:
            candidate = OUTPUT_DIR / f"candidate-{len(candidate_files) + 1:03d}.bin"
            atomic_write(output_descriptor, candidate.name, data)
            candidate_files.append(str(candidate))

        if depth < args.depth:
            def remaining_budget() -> int:
                return max(0, args.max_total_bytes - total_enqueued_bytes)

            if remaining_budget() == 0:
                byte_budget_exhausted = True
                continue
            for transform_name, decoded in transforms(
                data, args.max_bytes, remaining_budget
            ):
                if decoded is None:
                    byte_budget_exhausted = True
                    continue
                decoded_digest = hashlib.sha256(decoded).hexdigest()
                if decoded_digest in discovered:
                    continue
                if total_enqueued_bytes + len(decoded) > args.max_total_bytes:
                    byte_budget_exhausted = True
                    break
                discovered.add(decoded_digest)
                queue.append((depth + 1, [*path, transform_name], decoded))
                queued_bytes += len(decoded)
                total_enqueued_bytes += len(decoded)
                peak_queued_bytes = max(peak_queued_bytes, queued_bytes)

    report = {
        "ok": True,
        "input": str(args.input.resolve()),
        "nodes": len(records),
        "truncated": bool(queue) or byte_budget_exhausted,
        "limits": {
            "max_node_bytes": args.max_bytes,
            "max_total_bytes": args.max_total_bytes,
            "max_nodes": args.nodes,
            "max_depth": args.depth,
            "max_flags_per_node": args.max_flags_per_node,
            "max_flags_total": args.max_flags_total,
        },
        "bytes": {
            "processed": processed_bytes,
            "queued_current": queued_bytes,
            "queued_peak": peak_queued_bytes,
            "total_enqueued": total_enqueued_bytes,
            "budget_exhausted": byte_budget_exhausted,
        },
        "flags": sorted(all_flags),
        "flag_results": flag_results,
        "flags_truncated": flags_truncated,
        "candidate_files": candidate_files,
        "candidate_files_truncated": sum(bool(record["flags"]) for record in records)
        > len(candidate_files),
        "records": records,
    }
    report_path = OUTPUT_DIR / "decode.json"
    atomic_write(
        output_descriptor,
        report_path.name,
        (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
    )
    print(
        json.dumps(
            {
                "ok": True,
                "nodes": len(records),
                "flags": sorted(all_flags),
                "report": str(report_path),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
