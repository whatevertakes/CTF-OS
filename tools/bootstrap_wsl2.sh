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
  docker-compose-v2
  file
  gdb
  gcc-avr
  git
  jq
  libffi-dev
  libssl-dev
  netcat-openbsd
  nodejs
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
  binwalk
  checksec
  ffuf
  foremost
  gobuster
  libimage-exiftool-perl
  nmap
  patchelf
  ripgrep
  jadx
  radare2
  sagemath
  socat
  steghide
  yara
)
JADX_VERSION="1.5.5"
APKTOOL_VERSION="3.0.2"
PWNINIT_VERSION="3.3.1"

usage() {
  cat <<'EOF'
사용법: tools/bootstrap_wsl2.sh [--minimal] [--skip-apt] [--skip-python] [--skip-preflight]

팀 기준 WSL2 CTF 워크스페이스를 설정합니다.
  - 기본 Ubuntu 패키지 설치
  - 사용 가능한 CTF parity 도구 설치
  - .venv 생성
  - requirements.txt 설치
  - 현재 클론 경로에 맞는 .codex/config.toml 생성
  - tools/preflight_check.py --strict-optional 실행

무거운 parity 도구를 건너뛰고 기본 점검만 하려면 --minimal을 사용하세요.
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
      echo "알 수 없는 인자: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

apt_package_available() {
  local candidate
  candidate="$(apt-cache policy "$1" 2>/dev/null | awk '/Candidate:/ {print $2; exit}')"
  [ -n "$candidate" ] && [ "$candidate" != "(none)" ]
}

install_available_apt_packages() {
  local packages=()
  local package
  for package in "$@"; do
    if apt_package_available "$package"; then
      packages+=("$package")
    else
      echo "WARN apt 패키지를 사용할 수 없습니다: $package" >&2
    fi
  done
  if [ "${#packages[@]}" -gt 0 ]; then
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}"
  fi
}

install_npm_if_needed() {
  if command -v npm >/dev/null 2>&1 && command -v npx >/dev/null 2>&1; then
    return 0
  fi
  if ! apt_package_available npm; then
    echo "WARN apt 패키지를 사용할 수 없습니다: npm" >&2
    return 0
  fi
  if ! sudo DEBIAN_FRONTEND=noninteractive apt-get install -y npm; then
    echo "WARN npm apt 설치를 건너뜁니다. NodeSource nodejs 환경에서는 npm이 nodejs 패키지에 포함될 수 있습니다." >&2
  fi
}

playwright_browser_available() {
  "$ROOT/.codex/bin/playwright-mcp-codex.sh" --print-browser >/dev/null 2>&1
}

install_playwright_browser_if_needed() {
  if playwright_browser_available; then
    return 0
  fi
  if ! command -v npx >/dev/null 2>&1; then
    echo "WARN npx가 없어 Playwright Chromium 설치를 건너뜁니다." >&2
    return 0
  fi
  npx --yes playwright@latest install chromium
}

command_succeeds() {
  timeout 30 "$@" >/dev/null 2>&1
}

sync_agent_skill_links() {
  mkdir -p "$ROOT/.agents/skills"
  local skill_dir
  local name
  for skill_dir in "$ROOT"/skills/*; do
    [ -f "$skill_dir/SKILL.md" ] || continue
    name="$(basename "$skill_dir")"
    ln -sfn "../../skills/$name" "$ROOT/.agents/skills/$name"
  done
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

install_rsactftool_fallback() {
  if command_succeeds RsaCtfTool --help; then
    return 0
  fi

  local dest="$HOME/.local/opt/ctf-tools/rsactftool"
  mkdir -p "$dest" "$HOME/.local/bin"
  "$PYTHON" -m venv "$dest/.venv"
  "$dest/.venv/bin/python" -m pip install -U pip "setuptools<81" wheel
  "$dest/.venv/bin/python" -m pip install -U "git+https://github.com/RsaCtfTool/RsaCtfTool.git"
  cat >"$HOME/.local/bin/RsaCtfTool" <<EOF
#!/usr/bin/env bash
exec "$dest/.venv/bin/RsaCtfTool" "\$@"
EOF
  chmod +x "$HOME/.local/bin/RsaCtfTool"
}

install_pwninit_fallback() {
  if command_succeeds pwninit --version; then
    return 0
  fi

  mkdir -p "$HOME/.local/bin" "$ROOT/.cache/tools"
  curl -L \
    "https://github.com/io12/pwninit/releases/download/$PWNINIT_VERSION/pwninit" \
    -o "$ROOT/.cache/tools/pwninit-$PWNINIT_VERSION"
  install -m 0755 "$ROOT/.cache/tools/pwninit-$PWNINIT_VERSION" "$HOME/.local/bin/pwninit"
}

install_mcp_reverse_proxy_compat() {
  mkdir -p "$HOME/.local/bin"
  write_mcp_reverse_proxy_wrapper "$HOME/.local/bin/mcp-reverse-proxy"
  if [ -d "$ROOT/.venv/bin" ]; then
    write_mcp_reverse_proxy_wrapper "$ROOT/.venv/bin/mcp-reverse-proxy"
  fi
}

write_mcp_reverse_proxy_wrapper() {
  local wrapper="$1"
  cat >"$wrapper" <<EOF
#!/usr/bin/env bash
if [ -x "$ROOT/.venv/bin/mcp-proxy" ]; then
  exec "$ROOT/.venv/bin/mcp-proxy" "\$@"
fi
exec mcp-proxy "\$@"
EOF
  chmod +x "$wrapper"
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
    if ! command -v zsteg >/dev/null 2>&1; then
      sudo gem install zsteg
    fi
  else
    echo "WARN gem을 사용할 수 없어 one_gadget, seccomp-tools, zsteg를 설치하지 못했습니다." >&2
  fi

  install_jadx_fallback
  install_apktool_fallback
  install_radare2_fallback
  install_rsactftool_fallback
  install_pwninit_fallback
  install_mcp_reverse_proxy_compat
}

mkdir -p \
  "$ROOT/.agents/skills" \
  "$ROOT/.cache/xdg" \
  "$ROOT/.cache/matplotlib" \
  "$ROOT/.cache/numba" \
  "$ROOT/.cache/pip" \
  "$ROOT/.cache/uv" \
  "$ROOT/.cache/npm" \
  "$ROOT/.cache/python-pycache" \
  "$ROOT/.cache/tools"

sync_agent_skill_links

if [ "$SKIP_APT" -eq 0 ]; then
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "기본 WSL2 부트스트랩에는 apt-get이 필요합니다. 패키지를 직접 관리하려면 --skip-apt로 다시 실행하세요." >&2
    exit 1
  fi
  sudo apt-get update
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${APT_PACKAGES[@]}"
  install_npm_if_needed
fi

if [ "$SKIP_PYTHON" -eq 0 ]; then
  "$PYTHON" -m venv "$ROOT/.venv"
  "$ROOT/.venv/bin/python" -m pip install -U pip setuptools wheel
  "$ROOT/.venv/bin/python" -m pip install -r "$ROOT/requirements.txt"
fi

if [ "$TEAM_PARITY" -eq 1 ]; then
  install_team_parity_tools
  install_playwright_browser_if_needed
fi

CONFIG_PYTHON="$ROOT/.venv/bin/python"
if [ ! -x "$CONFIG_PYTHON" ]; then
  CONFIG_PYTHON="$PYTHON"
fi
"$CONFIG_PYTHON" "$ROOT/tools/localize_codex_config.py" --root "$ROOT"

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

부트스트랩 완료.
워크스페이스: $ROOT

새 셸에서는 다음을 실행하세요.
  cd "$ROOT"
  . .codex/env.sh

Docker 권한 오류가 나면 WSL2 사용자를 docker 그룹에 추가하고 셸을 다시 시작하세요.
  sudo usermod -aG docker "\$USER"
EOF
