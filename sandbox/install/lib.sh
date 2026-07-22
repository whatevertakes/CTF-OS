#!/usr/bin/env bash
set -Eeuo pipefail

export DEBIAN_FRONTEND=noninteractive
export PIP_DISABLE_PIP_VERSION_CHECK=1

apt_install() {
  apt-get update
  apt-get install -y --no-install-recommends "$@"
  rm -rf /var/lib/apt/lists/*
}

pip_install() {
  python3 -m pip install --break-system-packages --no-cache-dir "$@"
}

download() {
  local url="$1" destination="$2"
  curl --fail --location --retry 3 --silent --show-error "$url" --output "$destination"
}

download_sha256() {
  local url="$1" destination="$2" expected_sha256="$3"
  [[ "$expected_sha256" =~ ^[[:xdigit:]]{64}$ ]] || {
    echo "invalid SHA-256 for $url" >&2
    exit 1
  }
  download "$url" "$destination"
  printf '%s  %s\n' "$expected_sha256" "$destination" | sha256sum --check --strict -
}

require_command() {
  command -v "$1" >/dev/null || { echo "required command missing after install: $1" >&2; exit 1; }
}

require_import() {
  python3 -c "import $1" || { echo "required Python import missing after install: $1" >&2; exit 1; }
}
