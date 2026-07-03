#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
python3 work/build_payload.py >/dev/null
python3 work/solve.py --host host8.dreamhack.games --port 16487
