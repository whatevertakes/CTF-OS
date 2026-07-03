#!/usr/bin/env bash
set -euo pipefail

CHALLENGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$CHALLENGE_DIR/work/solve.py"
