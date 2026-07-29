#!/usr/local/bin/sage
"""Small RSA starter for JSON parameters.

Accepted keys are n, e, c and optional p, q, or d. Values may be JSON numbers
or strings such as "0xdeadbeef".
"""

import argparse
import base64
import json
import re
import sys
from pathlib import Path

from Crypto.Util.number import long_to_bytes
from sage.all import Integer, inverse_mod, power_mod

SCRIPT_DIR = Path(sys.argv[0]).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
try:
    from safe_output import atomic_write, open_output_dir
except ModuleNotFoundError as exc:
    if exc.name != "safe_output":
        raise
    print(
        f"rsa.sage: required helper is missing: {SCRIPT_DIR / 'safe_output.py'}",
        file=sys.stderr,
    )
    raise SystemExit(1) from exc

OUTPUT_DIR = Path("/work/crypto")
FLAG_RE = re.compile(rb"[A-Za-z0-9_]{2,20}\{[^}\r\n]{1,200}\}")


def as_integer(value, name):
    if isinstance(value, str):
        try:
            return Integer(value, 0)
        except ValueError as exc:
            raise ValueError(f"{name} is not a valid integer: {value}") from exc
    return Integer(value)


def text_views(data):
    views = {}
    for encoding in ("utf-8", "cp949", "euc-kr"):
        try:
            views[encoding] = data.decode(encoding)
        except UnicodeDecodeError:
            pass
    return views


def parse_args():
    parser = argparse.ArgumentParser(
        description="Try supplied RSA factors/private exponent or an exact low-exponent root."
    )
    parser.add_argument("params", type=Path, help="JSON file containing n, e, c and optional p/q/d")
    args = parser.parse_args()
    if not args.params.is_file():
        parser.error(f"parameter file does not exist: {args.params}")
    return args


def recover_plaintext(params):
    for required in ("n", "e", "c"):
        if required not in params:
            raise ValueError(f"missing required JSON key: {required}")
    n = as_integer(params["n"], "n")
    e = as_integer(params["e"], "e")
    c = as_integer(params["c"], "c")

    if "d" in params:
        d = as_integer(params["d"], "d")
        return power_mod(c, d, n), "supplied-private-exponent"

    if "p" in params or "q" in params:
        if "p" not in params or "q" not in params:
            raise ValueError("p and q must be supplied together")
        p = as_integer(params["p"], "p")
        q = as_integer(params["q"], "q")
        if p * q != n:
            raise ValueError("p * q does not equal n")
        phi = (p - 1) * (q - 1)
        d = inverse_mod(e, phi)
        return power_mod(c, d, n), "supplied-factors"

    root, exact = c.nth_root(e, truncate_mode=True)
    if exact and power_mod(root, e, n) == c:
        return root, "exact-low-exponent-root"
    raise ValueError("no trivial recovery succeeded; add p, q, or d, or extend this template")


def main():
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
    try:
        params = json.loads(args.params.read_text(encoding="utf-8"))
        plaintext_integer, method = recover_plaintext(params)
        plaintext = long_to_bytes(int(plaintext_integer))
    except (OSError, ArithmeticError, ValueError, TypeError, json.JSONDecodeError) as exc:
        result = {"ok": False, "error": type(exc).__name__, "message": str(exc)}
        atomic_write(
            output_descriptor,
            "rsa-result.json",
            (json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
        )
        print(json.dumps(result, ensure_ascii=False))
        return 1

    plaintext_path = OUTPUT_DIR / "plaintext.bin"
    atomic_write(output_descriptor, plaintext_path.name, plaintext)
    result = {
        "ok": True,
        "method": method,
        "plaintext": str(plaintext_path),
        "length": len(plaintext),
        "hex": plaintext.hex(),
        "base64": base64.b64encode(plaintext).decode("ascii"),
        "text": text_views(plaintext),
        "flags": [
            item.decode("utf-8", errors="replace") for item in FLAG_RE.findall(plaintext)
        ],
    }
    atomic_write(
        output_descriptor,
        "rsa-result.json",
        (json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode("utf-8"),
    )
    print(json.dumps(result, ensure_ascii=False))
    return 0


# Sage evaluates .sage files with its own module name, so call the CLI directly.
_exit_code = main()
if _exit_code:
    raise SystemExit(_exit_code)
