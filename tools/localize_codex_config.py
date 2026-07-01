#!/usr/bin/env python3
"""Generate the local Codex config for this clone path."""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path


TOKEN = "__CTF_WORKSPACE_ROOT__"


def toml_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        default=None,
        help="workspace root; defaults to the parent of this script directory",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(args.root).expanduser().resolve() if args.root else Path(__file__).resolve().parents[1]
    codex_dir = root / ".codex"
    template_path = codex_dir / "config.toml.template"
    config_path = codex_dir / "config.toml"

    try:
        template = template_path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"FAIL Codex 설정 템플릿을 읽을 수 없습니다: {exc}", file=sys.stderr)
        return 1

    if TOKEN not in template:
        print(f"FAIL Codex 설정 템플릿에 {TOKEN} 토큰이 없습니다.", file=sys.stderr)
        return 1

    config = template.replace(TOKEN, toml_escape(str(root)))
    try:
        tomllib.loads(config)
    except tomllib.TOMLDecodeError as exc:
        print(f"FAIL 생성된 Codex 설정이 올바른 TOML이 아닙니다: {exc}", file=sys.stderr)
        return 1

    config_path.write_text(config, encoding="utf-8")
    print(f"PASS 로컬 Codex 설정 갱신: {config_path}")
    print(f"PASS 워크스페이스 경로: {root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
