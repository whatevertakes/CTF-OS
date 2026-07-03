#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"
OPT_ROOT="${CTF_ADVANCED_TOOLS_ROOT:-$HOME/.local/opt/ctf-tools}"
BIN_DIR="$HOME/.local/bin"

APT_PACKAGES=(
  adb
  gir1.2-gtk-3.0
  gnuradio
  sleuthkit
  stegseek
)

PIP_TOOLS=(
  objection
  halmos
  garak
  urh
)

usage() {
  cat <<'EOF'
Usage: tools/install_advanced_ctf_tools.sh [--skip-apt] [--skip-ghidra] [--skip-pwndbg] [--skip-garak]

Installs advanced, target-specific CTF tools into user-local paths:
  - apt: adb, GNU Radio, Sleuth Kit, stegseek
  - user venv wrappers: objection, halmos, garak, urh
  - user checkouts/downloads: pwndbg, Ghidra

Run from a terminal with sudo available. These tools are intentionally not part
of the default team setup because garak/Ghidra/GNU Radio are large.
EOF
}

SKIP_APT=0
SKIP_GHIDRA=0
SKIP_PWNDBG=0
SKIP_GARAK=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --skip-apt) SKIP_APT=1 ;;
    --skip-ghidra) SKIP_GHIDRA=1 ;;
    --skip-pwndbg) SKIP_PWNDBG=1 ;;
    --skip-garak) SKIP_GARAK=1 ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

mkdir -p "$OPT_ROOT" "$BIN_DIR" "$ROOT/.cache/tools"

install_apt_tools() {
  if [ "$SKIP_APT" -eq 1 ]; then
    return 0
  fi
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "WARN apt-get unavailable; skipping apt advanced tools" >&2
    return 0
  fi
  sudo -v
  sudo apt-get update
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${APT_PACKAGES[@]}"
}

install_pip_tool() {
  local name="$1"
  shift
  local dest="$OPT_ROOT/$name"
  "$PYTHON" -m venv "$dest/.venv"
  "$dest/.venv/bin/python" -m pip install -U pip setuptools wheel
  "$dest/.venv/bin/python" -m pip install -U "$@"
  if [ -x "$dest/.venv/bin/$name" ]; then
    ln -sfn "$dest/.venv/bin/$name" "$BIN_DIR/$name"
  fi
}

install_pip_tools() {
  local tool
  for tool in "${PIP_TOOLS[@]}"; do
    if [ "$tool" = "garak" ] && [ "$SKIP_GARAK" -eq 1 ]; then
      continue
    fi
    install_pip_tool "$tool" "$tool"
  done
}

install_pwndbg() {
  if [ "$SKIP_PWNDBG" -eq 1 ]; then
    return 0
  fi
  local dest="$OPT_ROOT/pwndbg"
  if [ ! -d "$dest/.git" ]; then
    git clone https://github.com/pwndbg/pwndbg "$dest"
  else
    git -C "$dest" pull --ff-only
  fi
  (cd "$dest" && ./setup.sh)
  cat >"$BIN_DIR/pwndbg-gdb" <<'EOF'
#!/usr/bin/env bash
exec gdb -q "$@"
EOF
  chmod +x "$BIN_DIR/pwndbg-gdb"
}

install_ghidra() {
  if [ "$SKIP_GHIDRA" -eq 1 ]; then
    return 0
  fi
  "$PYTHON" - <<'PY'
import json
import os
import pathlib
import shutil
import shlex
import stat
import urllib.request
import zipfile

opt_root = pathlib.Path(os.environ["OPT_ROOT"])
bin_dir = pathlib.Path(os.environ["BIN_DIR"])
cache = pathlib.Path(os.environ["ROOT"]) / ".cache" / "tools"
api = "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest"
with urllib.request.urlopen(api, timeout=30) as response:
    release = json.load(response)

asset = None
for candidate in release.get("assets", []):
    name = candidate.get("name", "")
    if name.endswith(".zip") and "PUBLIC" in name:
        asset = candidate
        break
if asset is None:
    raise SystemExit("missing Ghidra PUBLIC zip release asset")

zip_path = cache / asset["name"]
if not zip_path.exists():
    urllib.request.urlretrieve(asset["browser_download_url"], zip_path)

with zipfile.ZipFile(zip_path) as archive:
    top = archive.namelist()[0].split("/")[0]
    dest = opt_root / top
    if not dest.exists():
        archive.extractall(opt_root)

for script in [dest / "ghidraRun", dest / "support" / "analyzeHeadless"]:
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
for script in dest.rglob("*.sh"):
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

latest = opt_root / "ghidra-latest"
if latest.is_symlink() or latest.is_file():
    latest.unlink()
elif latest.is_dir():
    shutil.rmtree(latest)
latest.symlink_to(dest.name)

(bin_dir / "ghidra").write_text(
    f"#!/usr/bin/env bash\nexec {shlex.quote(str(latest / 'ghidraRun'))} \"$@\"\n",
    encoding="utf-8",
)
(bin_dir / "ghidra-analyzeHeadless").write_text(
    f"#!/usr/bin/env bash\nexec {shlex.quote(str(latest / 'support' / 'analyzeHeadless'))} \"$@\"\n",
    encoding="utf-8",
)
(bin_dir / "ghidra-check").write_text(
    f"#!/usr/bin/env bash\nprintf '%s\\n' '{release['tag_name']}'\n"
    f"test -x {shlex.quote(str(latest / 'ghidraRun'))}\n"
    f"test -x {shlex.quote(str(latest / 'support' / 'analyzeHeadless'))}\n",
    encoding="utf-8",
)
for wrapper in ["ghidra", "ghidra-analyzeHeadless", "ghidra-check"]:
    path = bin_dir / wrapper
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
PY
}

install_gnuradio_wrapper() {
  cat >"$BIN_DIR/gnuradio-companion-clean" <<'EOF'
#!/usr/bin/env bash
export PYTHONNOUSERSITE=1
unset PYTHONPATH
exec /usr/bin/gnuradio-companion "$@"
EOF
  chmod +x "$BIN_DIR/gnuradio-companion-clean"
}

install_apt_tools
install_pip_tools
install_pwndbg
ROOT="$ROOT" OPT_ROOT="$OPT_ROOT" BIN_DIR="$BIN_DIR" install_ghidra
install_gnuradio_wrapper

cat <<EOF

Advanced CTF tools installed.
Run:
  . .codex/env.sh
  python3 tools/preflight_check.py --deep --category pwn
  python3 tools/preflight_check.py --deep --category rev
  python3 tools/preflight_check.py --deep --category mobile
  python3 tools/preflight_check.py --deep --category web3
  python3 tools/preflight_check.py --deep --category ai-ml
  python3 tools/preflight_check.py --deep --category hardware-rf
EOF
