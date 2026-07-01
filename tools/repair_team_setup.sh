#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "== repair: sync main =="
git fetch origin main
if ! git diff --quiet -- .codex/config.toml; then
  echo "restoring local .codex/config.toml before pulling main"
  git checkout -- .codex/config.toml
fi
git pull --ff-only origin main

echo "== repair: refresh local config =="
tools/bootstrap_wsl2.sh --skip-apt --skip-python --skip-preflight

echo "== repair: load workspace env for checks =="
# shellcheck disable=SC1091
. .codex/env.sh

echo "== repair: validation =="
python3 tools/preflight_check.py --strict-optional
python3 tools/check_team_parity.py
codex mcp list

cat <<'EOF'

Repair complete.

Expected success markers:
  summary failures=0 warnings=0
  team parity summary failures=0
  codex mcp list shows angr, playwright, radare2

Restart Codex from this directory:
  cd ~/ctf_workspace
  . .codex/env.sh
  codex
EOF
