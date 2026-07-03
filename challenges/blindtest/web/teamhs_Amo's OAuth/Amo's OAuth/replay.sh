#!/usr/bin/env bash
set -euo pipefail

challenge_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
python3 "$challenge_dir/work/solve.py"
