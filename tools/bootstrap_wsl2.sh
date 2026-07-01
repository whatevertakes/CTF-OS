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
  default-jre
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
  ruby
  ruby-dev
  tshark
  unzip
  xz-utils
  avr-libc
)
PARITY_APT_CANDIDATES=(
  apktool
  jadx
  radare2
  sagemath
)
JADX_VERSION="1.5.5"
APKTOOL_VERSION="3.0.2"

usage() {
  cat <<'EOF'
Usage: tools/bootstrap_wsl2.sh [--minimal] [--skip-apt] [--skip-python] [--skip-preflight]

Bootstraps a team-parity WSL2 CTF workspace:
  - installs baseline Ubuntu packages
  - installs optional CTF parity tools when available
  - creates .venv
  - installs requirements.txt
  - rewrites .codex/config.toml absolute paths for this clone
  - runs tools/preflight_check.py --strict-optional

Use --minimal to skip heavyweight parity tools and run the baseline preflight.
EOF
}

SKIP_APT=0
SKIP_PYTHON=0
SKIP_PREFLIGHT=0
TEAM_PARITY=1
while [ "$#" -gt 0 ]; do
  case "$1" in
    --minimal) TEAM_PARITY=0 ;;
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

apt_package_available() {
  apt-cache show "$1" >/dev/null 2>&1
}

install_available_apt_packages() {
  local packages=()
  local package
  for package in "$@"; do
    if apt_package_available "$package"; then
      packages+=("$package")
    else
      echo "WARN apt package unavailable: $package" >&2
    fi
  done
  if [ "${#packages[@]}" -gt 0 ]; then
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}"
  fi
}

install_jadx_fallback() {
  if command -v jadx >/dev/null 2>&1; then
    return 0
  fi
  local dest="$HOME/.local/opt/revtools/jadx-$JADX_VERSION"
  mkdir -p "$HOME/.local/opt/revtools" "$HOME/.local/bin" "$ROOT/.cache/tools"
  curl -L \
    "https://github.com/skylot/jadx/releases/download/v$JADX_VERSION/jadx-$JADX_VERSION.zip" \
    -o "$ROOT/.cache/tools/jadx-$JADX_VERSION.zip"
  rm -rf "$dest"
  unzip -q "$ROOT/.cache/tools/jadx-$JADX_VERSION.zip" -d "$dest"
  ln -sf "$dest/bin/jadx" "$HOME/.local/bin/jadx"
}

install_apktool_fallback() {
  if command -v apktool >/dev/null 2>&1; then
    return 0
  fi
  mkdir -p "$HOME/.local/opt/revtools" "$HOME/.local/bin" "$ROOT/.cache/tools"
  curl -L \
    "https://github.com/iBotPeaches/Apktool/releases/download/v$APKTOOL_VERSION/apktool_$APKTOOL_VERSION.jar" \
    -o "$HOME/.local/opt/revtools/apktool.jar"
  cat >"$HOME/.local/bin/apktool" <<'EOF'
#!/usr/bin/env bash
exec java -jar "$HOME/.local/opt/revtools/apktool.jar" "$@"
EOF
  chmod +x "$HOME/.local/bin/apktool"
}

install_radare2_fallback() {
  if command -v r2 >/dev/null 2>&1 && { command -v r2mcp >/dev/null 2>&1 || [ -x "$HOME/.local/share/radare2/prefix/bin/r2mcp" ]; }; then
    return 0
  fi
  mkdir -p "$HOME/tools" "$HOME/.local/bin"
  if [ ! -d "$HOME/tools/radare2/.git" ]; then
    git clone --depth 1 https://github.com/radareorg/radare2 "$HOME/tools/radare2"
  else
    git -C "$HOME/tools/radare2" pull --ff-only || true
  fi
  "$HOME/tools/radare2/sys/install.sh" --install
  if [ -x "$HOME/tools/radare2/binr/radare2/radare2" ]; then
    ln -sf "$HOME/tools/radare2/binr/radare2/radare2" "$HOME/.local/bin/r2"
  fi
}

install_team_parity_tools() {
  if [ "$SKIP_APT" -eq 0 ]; then
    install_available_apt_packages "${PARITY_APT_CANDIDATES[@]}"
  fi

  if command -v gem >/dev/null 2>&1; then
    if ! command -v one_gadget >/dev/null 2>&1; then
      sudo gem install one_gadget
    fi
    if ! command -v seccomp-tools >/dev/null 2>&1; then
      sudo gem install seccomp-tools
    fi
  else
    echo "WARN gem unavailable; one_gadget and seccomp-tools were not installed" >&2
  fi

  install_jadx_fallback
  install_apktool_fallback
  install_radare2_fallback
}

if [ "$SKIP_APT" -eq 0 ]; then
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "apt-get is required for the default WSL2 bootstrap; rerun with --skip-apt to manage packages yourself." >&2
    exit 1
  fi
  sudo apt-get update
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${APT_PACKAGES[@]}"
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

if [ "$TEAM_PARITY" -eq 1 ]; then
  install_team_parity_tools
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
  if [ "$TEAM_PARITY" -eq 1 ]; then
    "$ROOT/.venv/bin/python" "$ROOT/tools/preflight_check.py" --strict-optional
  else
    "$ROOT/.venv/bin/python" "$ROOT/tools/preflight_check.py"
  fi
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
