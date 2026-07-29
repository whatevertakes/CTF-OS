#!/usr/local/bin/angr-python
"""Bounded-address angr starter for a symbolic stdin challenge."""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from pathlib import Path

import angr
import claripy
from safe_output import atomic_write, open_output_dir

OUTPUT_DIR = Path("/work/rev")
FLAG_RE = re.compile(rb"[A-Za-z0-9_]{2,20}\{[^}\r\n]{1,200}\}")


def address(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid address: {value}") from exc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Explore a binary toward --find with a fixed-length symbolic stdin."
    )
    parser.add_argument("binary", type=Path, help="challenge binary, normally under /challenge")
    parser.add_argument("--find", required=True, type=address, help="success address (for example 0x401234)")
    parser.add_argument("--avoid", action="append", default=[], type=address, help="failure address")
    parser.add_argument("--stdin-length", type=int, default=32, help="symbolic stdin bytes")
    parser.add_argument(
        "--allow-binary", action="store_true", help="do not constrain stdin bytes to printable ASCII"
    )
    args = parser.parse_args()
    if not args.binary.is_file():
        parser.error(f"binary does not exist: {args.binary}")
    if not 1 <= args.stdin_length <= 4096:
        parser.error("--stdin-length must be between 1 and 4096")
    return args


def main() -> int:
    args = parse_args()
    try:
        output_descriptor = open_output_dir(OUTPUT_DIR)
    except OSError as exc:
        print(
            json.dumps(
                {"ok": False, "error": "UnsafeOutputDirectory", "message": str(exc)}
            )
        )
        return 1
    logging.getLogger("angr").setLevel(logging.ERROR)
    logging.getLogger("cle").setLevel(logging.ERROR)
    binary = str(args.binary.resolve())
    project = angr.Project(binary, auto_load_libs=False)
    symbolic = claripy.BVS("stdin", 8 * args.stdin_length)
    stdin = angr.SimFileStream(name="stdin", content=symbolic, has_end=True)
    state = project.factory.full_init_state(args=[binary], stdin=stdin)
    if not args.allow_binary:
        for byte in symbolic.chop(8):
            state.solver.add(byte >= 0x20, byte <= 0x7E)

    manager = project.factory.simulation_manager(state)
    manager.explore(find=args.find, avoid=args.avoid, num_find=1)
    if not manager.found:
        result = {
            "ok": False,
            "reason": "no state reached the requested address",
            "active_states": len(manager.active),
            "deadended_states": len(manager.deadended),
        }
        atomic_write(
            output_descriptor,
            "angr-result.json",
            (json.dumps(result, indent=2) + "\n").encode("utf-8"),
        )
        print(json.dumps(result))
        return 1

    solution = manager.found[0].solver.eval(symbolic, cast_to=bytes)
    solution_path = OUTPUT_DIR / "angr-stdin.bin"
    atomic_write(output_descriptor, solution_path.name, solution)
    flags = [item.decode("utf-8", errors="replace") for item in FLAG_RE.findall(solution)]
    result = {
        "ok": True,
        "solution": str(solution_path),
        "length": len(solution),
        "hex": solution.hex(),
        "flags": flags,
    }
    atomic_write(
        output_descriptor,
        "angr-result.json",
        (json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
    )
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
