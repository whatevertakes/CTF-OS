#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: scripts/check-fresh-clone.sh [--help]

Validate that a fresh checkout contains the vendored CTF image source and run
the network-free source tests. This script does not build the large Docker
image; release/self-hosted runners may add that measured step separately.
EOF
}

if (($#)); then
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
fi

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "${repo_root}"

if [[ -e ctf-os-image/.git ]]; then
  echo "nested ctf-os-image/.git is forbidden" >&2
  exit 1
fi

entry=$(git ls-files -s -- ctf-os-image)
if grep -q '^160000 ' <<<"${entry}"; then
  echo "ctf-os-image is still a gitlink" >&2
  exit 1
fi

required=(
  ctf-os-image/.dockerignore
  ctf-os-image/AGENTS.md
  ctf-os-image/Dockerfile
  ctf-os-image/SOURCE.json
  ctf-os-image/capabilities.v2.json
  ctf-os-image/scripts/ctf-capabilities
  ctf-os-image/scripts/ctf-sqlite-readonly
  ctf-os-image/scripts/entrypoint.sh
  ctf-os-image/scripts/gen-manifest.sh
  ctf-os-image/templates/README.md
  ctf-os-image/templates/pwn/crash_oracle.py
  ctf-os-image/templates/pwn/runtime_snapshot.py
  ctf-os-image/templates/rev/inventory_v2.py
  ctf-os-image/templates/rev/safe_output.py
  ctf-os-image/templates/rev/stdin_exec.py
  ctf-os-image/tests/fixtures/pwn-crash-oracle.c
  ctf-os-image/tests/fixtures/rev-stdin-oracle.c
  ctf-os-image/tests/test-capability-contract.py
  ctf-os-image/tests/test-pwn-crash-oracle.py
  ctf-os-image/tests/test-pwn-runtime-snapshot.py
  ctf-os-image/tests/test-rev-inventory.py
  ctf-os-image/tests/test-rev-stdin-exec.py
  scripts/check-pwn-docker-crash.py
  scripts/check-rev-docker-proof.py
)
for path in "${required[@]}"; do
  if [[ ! -f "${path}" ]]; then
    echo "fresh clone is missing ${path}" >&2
    exit 1
  fi
  if ! git ls-files --error-unmatch -- "${path}" >/dev/null 2>&1; then
    echo "fresh clone input is not tracked: ${path}" >&2
    exit 1
  fi
done

python_bin=${CTFOS_PYTHON:-}
if [[ -z "${python_bin}" && -x .venv/bin/python ]]; then
  python_bin=.venv/bin/python
fi
if [[ -z "${python_bin}" ]]; then
  python_bin=$(command -v python3)
fi
"${python_bin}" -c \
  'import sys; assert sys.version_info >= (3, 13), "Python 3.13+ is required"'

"${python_bin}" -m unittest discover -s tests -p 'test_*.py'
"${python_bin}" ctf-os-image/tests/test-capability-contract.py
"${python_bin}" ctf-os-image/tests/test-tool-manifest.py
"${python_bin}" ctf-os-image/tests/test-browser-safety.py
"${python_bin}" ctf-os-image/tests/test-pwn-crash-oracle.py
"${python_bin}" ctf-os-image/tests/test-pwn-runtime-snapshot.py
"${python_bin}" ctf-os-image/tests/test-rev-inventory.py
"${python_bin}" ctf-os-image/tests/test-rev-stdin-exec.py
"${python_bin}" -m py_compile scripts/check-pwn-docker-crash.py
"${python_bin}" -m py_compile scripts/check-rev-docker-proof.py

for script in ctf-os-image/scripts/* ctf-os-image/tests/*.sh; do
  if [[ ! -f "${script}" ]]; then
    continue
  fi
  shebang=
  IFS= read -r shebang <"${script}" || true
  case "${shebang}" in
    *"bash"*|*"/sh"*)
      bash -n "${script}"
      ;;
  esac
done

echo "fresh-clone source verification: ok"
