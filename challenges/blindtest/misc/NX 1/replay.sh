#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

python3 work/exploit.py --host host3.dreamhack.games --port 12094 --delay 0.45
