#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

config="config.yaml"
image="ctf-os-sandbox:latest"
skip_image=0
skip_migrate=0
rebuild_image=0

usage() {
  echo "usage: scripts/deploy_ctf_os.sh [--config PATH] [--skip-image] [--skip-migrate] [--rebuild-image]"
}

while (($#)); do
  case "$1" in
    --config)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      config="$2"
      shift 2
      ;;
    --skip-image) skip_image=1; shift ;;
    --skip-migrate) skip_migrate=1; shift ;;
    --rebuild-image) rebuild_image=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

command -v uv >/dev/null 2>&1 || {
  echo "CTF-OS deployment requires uv: https://docs.astral.sh/uv/" >&2
  exit 1
}

echo "Installing locked CTF-OS dependencies..."
uv sync --frozen

if ((skip_migrate == 0)); then
  [[ -f "$config" ]] || {
    echo "Local config not found: $config" >&2
    echo "Create it once with: uv run ctf-os init \"CONTEST NAME\" --config \"$config\"" >&2
    echo "No config, database, incoming files, output, or TeamSync data were changed." >&2
    exit 1
  }
  echo "Applying transactional SQLite migrations through $config..."
  uv run ctf-os state migrate --config "$config"
fi

if ((skip_image == 0)); then
  command -v docker >/dev/null 2>&1 || {
    echo "Docker is required to build and verify $image; install/start Docker or rerun with --skip-image." >&2
    exit 1
  }
  docker info >/dev/null 2>&1 || {
    echo "Docker is installed but the daemon is unavailable; start Docker or rerun with --skip-image." >&2
    exit 1
  }

  if ((rebuild_image == 1)) || ! docker image inspect "$image" >/dev/null 2>&1; then
    echo "Building the shared sandbox image once..."
    docker build -f sandbox/Dockerfile.sandbox -t "$image" .
  else
    echo "Sandbox image already exists; reusing $image (use --rebuild-image to replace it)."
  fi
  scripts/verify_sandbox_image.sh "$image"
fi

echo "CTF-OS team deployment verification completed."
