#!/usr/bin/env bash
set -euo pipefail

export JAVA_HOME="${JAVA_HOME:-/usr/lib/jvm/java-21-openjdk-amd64}"
export GHIDRA_INSTALL_DIR="${GHIDRA_INSTALL_DIR:-/home/choijiwng/tools/ghidra_12.1_PUBLIC}"
PYGHIDRA_MCP_PROJECT_PATH="${PYGHIDRA_MCP_PROJECT_PATH:-/home/choijiwng/02_ctf_workspace/.cache/ghidra-mcp}"
mkdir -p "$PYGHIDRA_MCP_PROJECT_PATH"

for arg in "$@"; do
  case "$arg" in
    --project-path|--project-path=*) exec /home/choijiwng/tools/pyghidra-mcp/.venv/bin/pyghidra-mcp "$@" ;;
  esac
done

exec /home/choijiwng/tools/pyghidra-mcp/.venv/bin/pyghidra-mcp --project-path "$PYGHIDRA_MCP_PROJECT_PATH" "$@"
