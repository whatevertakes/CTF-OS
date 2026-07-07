#!/usr/bin/env bash

_codex_env_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export CTF_WORKSPACE_ROOT="$(cd "$_codex_env_dir/.." && pwd)"
export XDG_CACHE_HOME="$CTF_WORKSPACE_ROOT/.cache/xdg"
export MPLCONFIGDIR="$CTF_WORKSPACE_ROOT/.cache/matplotlib"
export NUMBA_CACHE_DIR="$CTF_WORKSPACE_ROOT/.cache/numba"
export PIP_CACHE_DIR="$CTF_WORKSPACE_ROOT/.cache/pip"
export UV_CACHE_DIR="$CTF_WORKSPACE_ROOT/.cache/uv"
export NPM_CONFIG_CACHE="$CTF_WORKSPACE_ROOT/.cache/npm"
export PYTHONPYCACHEPREFIX="$CTF_WORKSPACE_ROOT/.cache/python-pycache"

for _codex_cache_dir in \
  "$XDG_CACHE_HOME" \
  "$MPLCONFIGDIR" \
  "$NUMBA_CACHE_DIR" \
  "$PIP_CACHE_DIR" \
  "$UV_CACHE_DIR" \
  "$NPM_CONFIG_CACHE" \
  "$PYTHONPYCACHEPREFIX"; do
  [ -d "$_codex_cache_dir" ] || mkdir -p "$_codex_cache_dir"
done

if [ "${CODEX_KEEP_WINDOWS_PATH:-0}" != "1" ]; then
  _codex_new_path=""
  _codex_old_ifs=$IFS
  IFS=:
  for _codex_entry in $PATH; do
    [ -n "$_codex_entry" ] || continue
    case "$_codex_entry" in
      /mnt/c/*) continue ;;
    esac
    case ":$_codex_new_path:" in
      *":$_codex_entry:"*) continue ;;
    esac
    _codex_new_path="${_codex_new_path:+$_codex_new_path:}$_codex_entry"
  done
  IFS=$_codex_old_ifs
  PATH="$_codex_new_path"
fi

_codex_path_prepend() {
  [ -d "$1" ] || return 0
  case ":$PATH:" in
    *":$1:"*) ;;
    *) PATH="$1${PATH:+:$PATH}" ;;
  esac
}

_codex_path_append() {
  [ -d "$1" ] || return 0
  case ":$PATH:" in
    *":$1:"*) ;;
    *) PATH="${PATH:+$PATH:}$1" ;;
  esac
}

_codex_path_prepend "$CTF_WORKSPACE_ROOT/.codex/bin"
_codex_path_prepend "$CTF_WORKSPACE_ROOT/.venv/bin"
_codex_path_prepend "$HOME/.local/bin"
_codex_path_prepend "$HOME/go/bin"
_codex_path_prepend "$HOME/.cargo/bin"
_codex_path_prepend "$HOME/.dotnet/tools"
_codex_path_append "$HOME/.foundry/bin"
export PATH

unset _codex_cache_dir _codex_entry _codex_env_dir _codex_new_path _codex_old_ifs
unset -f _codex_path_prepend _codex_path_append
