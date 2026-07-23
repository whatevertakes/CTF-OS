#!/usr/bin/env bash
set -Eeuo pipefail

export DEBIAN_FRONTEND=noninteractive
export PIP_DISABLE_PIP_VERSION_CHECK=1
export PIP_DEFAULT_TIMEOUT=120
export PIP_RETRIES=5

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

register_python_library_dirs() {
  python3 - "$@" <<'PY'
from importlib.util import find_spec
from pathlib import Path
import sys

library_dirs = []
for module in sys.argv[1:]:
    spec = find_spec(module)
    if spec is None or not spec.submodule_search_locations:
        raise SystemExit(f"Python library package is missing: {module}")
    package = Path(next(iter(spec.submodule_search_locations)))
    library_dir = package / "lib"
    if not library_dir.is_dir():
        raise SystemExit(f"Python library directory is missing: {library_dir}")
    library_dirs.append(str(library_dir))

Path("/etc/ld.so.conf.d/ctf-os-python-libraries.conf").write_text(
    "\n".join(library_dirs) + "\n",
    encoding="utf-8",
)
PY
  ldconfig
}

link_python_library() {
  local module="$1" library="$2" link_name="$3" library_path
  library_path="$(
    python3 - "$module" "$library" <<'PY'
from importlib.util import find_spec
from pathlib import Path
import sys

module, library = sys.argv[1:]
spec = find_spec(module)
if spec is None or not spec.submodule_search_locations:
    raise SystemExit(f"Python library package is missing: {module}")
library_path = Path(next(iter(spec.submodule_search_locations))) / "lib" / library
if not library_path.is_file():
    raise SystemExit(f"Python library is missing: {library_path}")
print(library_path)
PY
  )"
  ln -sf "$library_path" "/usr/local/lib/$link_name"
  ldconfig
}
