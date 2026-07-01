#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"
APT_PACKAGES=(
  bash
  binutils
  binutils-avr
  build-essential
  ca-certificates
  curl
  docker.io
  file
  gdb
  gcc-avr
  git
  jq
  libffi-dev
  libssl-dev
  netcat-openbsd
  nodejs
  npm
  pkg-config
  python3
  python3-pip
  python3-venv
  unzip
  xz-utils
  avr-libc
)

usage() {
  cat <<'EOF'
Usage: tools/bootstrap_wsl2.sh [--skip-apt] [--skip-python] [--skip-preflight]

Bootstraps a lean WSL2 CTF workspace:
  - installs baseline Ubuntu packages
  - creates .venv
  - installs requirements.txt
  - rewrites .codex/config.toml absolute paths for this clone
  - runs tools/preflight_check.py
EOF
}

SKIP_APT=0
SKIP_PYTHON=0
SKIP_PREFLIGHT=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --skip-apt) SKIP_APT=1 ;;
    --skip-python) SKIP_PYTHON=1 ;;
    --skip-preflight) SKIP_PREFLIGHT=1 ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

if [ "$SKIP_APT" -eq 0 ]; then
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "apt-get is required for the default WSL2 bootstrap; rerun with --skip-apt to manage packages yourself." >&2
    exit 1
  fi
  sudo apt-get update
  sudo apt-get install -y "${APT_PACKAGES[@]}"
fi

mkdir -p \
  "$ROOT/.cache/xdg" \
  "$ROOT/.cache/matplotlib" \
  "$ROOT/.cache/numba" \
  "$ROOT/.cache/pip" \
  "$ROOT/.cache/uv" \
  "$ROOT/.cache/npm" \
  "$ROOT/.cache/python-pycache" \
  "$ROOT/.cache/tools"

if [ "$SKIP_PYTHON" -eq 0 ]; then
  "$PYTHON" -m venv "$ROOT/.venv"
  "$ROOT/.venv/bin/python" -m pip install -U pip setuptools wheel
  "$ROOT/.venv/bin/python" -m pip install -r "$ROOT/requirements.txt"
fi

"$ROOT/.venv/bin/python" - "$ROOT" <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
config = root / ".codex" / "config.toml"
text = config.read_text(encoding="utf-8")

env_values = {
    "BASH_ENV": root / ".codex" / "env.sh",
    "CTF_WORKSPACE_ROOT": root,
    "XDG_CACHE_HOME": root / ".cache" / "xdg",
    "MPLCONFIGDIR": root / ".cache" / "matplotlib",
    "NUMBA_CACHE_DIR": root / ".cache" / "numba",
    "PIP_CACHE_DIR": root / ".cache" / "pip",
    "UV_CACHE_DIR": root / ".cache" / "uv",
    "NPM_CONFIG_CACHE": root / ".cache" / "npm",
    "PYTHONPYCACHEPREFIX": root / ".cache" / "python-pycache",
}
env_line = "set = { " + ", ".join(f'{key} = "{value}"' for key, value in env_values.items()) + " }"

text = re.sub(
    r"(?m)^set = \{ .* \}$",
    env_line,
    text,
    count=1,
)
text = re.sub(
    r'(?m)^\[projects\."[^"]+"\]$',
    f'[projects."{root}"]',
    text,
    count=1,
)
text = re.sub(
    r'(?m)^command = ".*?/\.codex/bin/r2mcp-codex\.sh"$',
    f'command = "{root / ".codex" / "bin" / "r2mcp-codex.sh"}"',
    text,
    count=1,
)
config.write_text(text, encoding="utf-8")
PY

if [ "$SKIP_PREFLIGHT" -eq 0 ]; then
  # shellcheck disable=SC1091
  . "$ROOT/.codex/env.sh"
  "$ROOT/.venv/bin/python" "$ROOT/tools/preflight_check.py"
fi

cat <<EOF

Bootstrap complete.
Workspace: $ROOT

For new shells:
  cd "$ROOT"
  . .codex/env.sh

If Docker reports permission errors, add your WSL2 user to the docker group and restart the shell:
  sudo usermod -aG docker "\$USER"
EOF
