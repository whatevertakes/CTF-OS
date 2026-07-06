#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

usage() {
  cat <<'EOF'
Usage: tools/setup_workspace.sh <profile> [options]

Single setup entrypoint for the CTF workspace.

Profiles:
  team        Winning-mode team setup: bootstrap, parity, MCP, advanced tools, deep checks.
  bootstrap   Compatibility bootstrap for repair/manual package management.
  advanced    Compatibility alias for advanced CTF tool refresh only.
  references  Materialize and index Level 2 local reference cache.
  verify      Run local validation gates without installing tools.
  repair      Fast-forward from origin/main, refresh local config, and verify.

Common examples:
  tools/setup_workspace.sh team --branch <github-user>
  tools/setup_workspace.sh team --branch <github-user> --skip-garak --references
  tools/setup_workspace.sh bootstrap --skip-apt
  tools/setup_workspace.sh advanced --skip-garak
  tools/setup_workspace.sh references
  tools/setup_workspace.sh verify --selftests
  tools/setup_workspace.sh repair

Compatibility wrappers remain for older docs and muscle memory:
  tools/team_member_setup.sh
  tools/bootstrap_wsl2.sh
  tools/install_advanced_ctf_tools.sh
  tools/repair_team_setup.sh
EOF
}

if [ "$#" -eq 0 ]; then
  usage >&2
  exit 2
fi

PROFILE="$1"
shift

run() {
  echo
  echo "== $* =="
  "$@"
}

load_env_if_present() {
  if [ -f "$ROOT/.codex/env.sh" ]; then
    # shellcheck disable=SC1091
    . "$ROOT/.codex/env.sh"
  fi
}

setup_references() {
  local jobs="${1:-4}"
  load_env_if_present
  run python3 tools/reference_refresh.py --materialize-all --jobs "$jobs"
  run python3 tools/reference_index.py --all --max-files-per-ref 120
  run python3 tools/reference_digest_check.py
  run python3 tools/check_references.py
}

verify_workspace() {
  local selftests=0
  local strict=1
  local corpus=1
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --selftests) selftests=1 ;;
      --no-strict) strict=0 ;;
      --no-corpus) corpus=0 ;;
      -h|--help)
        cat <<'EOF'
Usage: tools/setup_workspace.sh verify [--selftests] [--no-strict] [--no-corpus]
EOF
        return 0
        ;;
      *)
        echo "FAIL unknown verify option: $1" >&2
        return 2
        ;;
    esac
    shift
  done

  load_env_if_present
  if [ "$strict" -eq 1 ]; then
    run python3 tools/preflight_check.py --strict-optional
  else
    run python3 tools/preflight_check.py
  fi
  run python3 tools/check_team_parity.py
  run python3 tools/check_level3_tool_routing.py
  run python3 tools/reference_digest_check.py
  if [ "$corpus" -eq 1 ]; then
    run python3 tools/evaluate_corpus.py
  fi
  run python3 tools/regression_check.py

  if [ "$selftests" -eq 1 ]; then
    run python3 benchmarks/level2_selftest.py
    run python3 benchmarks/level3_selftest.py
    run python3 benchmarks/level4_selftest.py
    run python3 benchmarks/level5_selftest.py
    run python3 benchmarks/level6_selftest.py
  fi
}

case "$PROFILE" in
  bootstrap)
    exec tools/bootstrap_wsl2.sh "$@"
    ;;
  advanced)
    exec tools/install_advanced_ctf_tools.sh "$@"
    ;;
  references)
    jobs=4
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --jobs)
          if [ "$#" -lt 2 ]; then
            echo "FAIL --jobs requires a value" >&2
            exit 2
          fi
          jobs="$2"
          shift
          ;;
        -h|--help)
          cat <<'EOF'
Usage: tools/setup_workspace.sh references [--jobs N]
EOF
          exit 0
          ;;
        *)
          echo "FAIL unknown references option: $1" >&2
          exit 2
          ;;
      esac
      shift
    done
    setup_references "$jobs"
    ;;
  verify)
    verify_workspace "$@"
    ;;
  team)
    references=0
    pass_args=()
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --references)
          references=1
          ;;
        *)
          pass_args+=("$1")
          ;;
      esac
      shift
    done
    run tools/team_member_setup.sh "${pass_args[@]}"
    if [ "$references" -eq 1 ]; then
      setup_references 4
    fi
    ;;
  repair)
    references=0
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --references)
          references=1
          ;;
        -h|--help)
          cat <<'EOF'
Usage: tools/setup_workspace.sh repair [--references]
EOF
          exit 0
          ;;
        *)
          echo "FAIL unknown repair option: $1" >&2
          exit 2
          ;;
      esac
      shift
    done
    run tools/repair_team_setup.sh
    if [ "$references" -eq 1 ]; then
      setup_references 4
    fi
    ;;
  -h|--help)
    usage
    ;;
  *)
    echo "FAIL unknown setup profile: $PROFILE" >&2
    usage >&2
    exit 2
    ;;
esac
