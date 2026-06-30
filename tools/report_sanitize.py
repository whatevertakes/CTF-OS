#!/usr/bin/env python3
"""Write redacted text summaries without modifying raw evidence."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FLAG_PATTERN = re.compile(r"\b(?:FLAG|CTF|DH|SEKAI)\{[^}\r\n]{1,300}\}", re.IGNORECASE)
SECRET_ASSIGNMENT = re.compile(
    r"(?im)^([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY)[A-Z0-9_]*\s*=\s*).+$"
)
BEARER_TOKEN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}")
PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)


def fail(message: str, code: int = 1) -> None:
    print(f"report_sanitize: {message}", file=sys.stderr)
    raise SystemExit(code)


def resolve_input(value: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = ROOT / path
    try:
        path.resolve().relative_to(ROOT)
    except ValueError:
        fail(f"input must stay under {ROOT}: {value}", code=2)
    if not path.is_file():
        fail(f"input file does not exist: {value}", code=2)
    return path.resolve()


def resolve_output(value: str, *, force: bool) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = ROOT / path
    try:
        path.resolve().relative_to(ROOT)
    except ValueError:
        fail(f"output must stay under {ROOT}: {value}", code=2)
    if path.exists() and not force:
        fail(f"output exists; rerun with --force to overwrite: {value}", code=2)
    return path.resolve()


def default_output(path: Path) -> Path:
    if path.name.endswith(".log"):
        return path.with_name(f"{path.stem}.summary.md")
    return path.with_name(f"{path.name}.redacted.md")


def sanitize_text(text: str) -> str:
    redacted = PRIVATE_KEY_BLOCK.sub("<REDACTED_PRIVATE_KEY>", text)
    redacted = FLAG_PATTERN.sub("<REDACTED_FLAG>", redacted)
    redacted = BEARER_TOKEN.sub("Bearer <REDACTED_TOKEN>", redacted)
    redacted = SECRET_ASSIGNMENT.sub(r"\1<REDACTED_SECRET>", redacted)
    return redacted


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input")
    parser.add_argument("--output", help="redacted output path; defaults beside input")
    parser.add_argument("--force", action="store_true", help="overwrite an existing output file")
    parser.add_argument("--check", action="store_true", help="fail if redaction markers are still present after sanitizing")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    source = resolve_input(args.input)
    output = resolve_output(args.output, force=args.force) if args.output else default_output(source)
    if output.exists() and not args.force:
        fail(f"output exists; rerun with --force to overwrite: {output.relative_to(ROOT)}", code=2)
    text = source.read_text(encoding="utf-8", errors="replace")
    redacted = sanitize_text(text)
    if args.check and (FLAG_PATTERN.search(redacted) or PRIVATE_KEY_BLOCK.search(redacted)):
        fail("sanitized output still contains sensitive markers")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(redacted, encoding="utf-8")
    print(f"report_sanitize wrote {output.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
