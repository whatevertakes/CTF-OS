#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

# shellcheck disable=SC1091
. .codex/env.sh

run_optional() {
  local label="$1"
  shift
  printf '%-24s ' "$label"
  "$@" 2>&1 | head -1 || true
}

show_path() {
  local command="$1"
  printf '%-24s ' "path $command"
  command -v "$command" || true
}

echo "== workspace =="
pwd
echo "CTF_WORKSPACE_ROOT=$CTF_WORKSPACE_ROOT"

echo "== paths =="
show_path angr-mcp
show_path checksec
show_path ROPgadget
show_path ropper
show_path r2
show_path r2mcp
show_path npx

echo "== core =="
run_optional git git --version
run_optional python3 python3 --version
run_optional venv-python .venv/bin/python --version
run_optional docker docker --version
docker info --format 'docker server {{.ServerVersion}}' 2>/dev/null || echo "docker server unavailable"
run_optional gcc gcc --version
run_optional gdb gdb --version
run_optional node node --version
run_optional npm npm --version
run_optional npx npx --version

echo "== python packages =="
.venv/bin/python - <<'PY'
import importlib.metadata as md

for package in [
    "requests",
    "httpx",
    "aiohttp",
    "beautifulsoup4",
    "lxml",
    "flask",
    "jinja2",
    "pwntools",
    "sqlmap",
    "defusedxml",
    "PyYAML",
    "angr",
    "capstone",
    "pefile",
    "ropper",
    "unicorn",
]:
    try:
        print(f"{package}=={md.version(package)}")
    except md.PackageNotFoundError:
        print(f"MISSING {package}")
PY

echo "== pwn/rev tools =="
run_optional checksec checksec --version
run_optional ROPgadget ROPgadget --version
run_optional ropper ropper --version
run_optional one_gadget one_gadget --version
run_optional seccomp-tools seccomp-tools --version
run_optional r2 r2 -v
run_optional r2mcp-wrapper .codex/bin/r2mcp-codex.sh --help

echo "== mobile/forensics/math =="
run_optional jadx jadx --version
run_optional apktool apktool --version
run_optional sage sage --version
run_optional tshark tshark --version

echo "== mcp =="
codex mcp list

echo "== final checks =="
python3 tools/preflight_check.py --strict-optional | tail -5
python3 tools/check_team_parity.py | tail -5
