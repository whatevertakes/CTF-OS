#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"
VENV_PYTHON="$ROOT/.venv/bin/python"
OPT_ROOT="${CTF_ADVANCED_TOOLS_ROOT:-$HOME/.local/opt/ctf-tools}"
BIN_DIR="$HOME/.local/bin"

APT_PACKAGES=(
  adb
  binwalk
  ffuf
  fplll-tools
  foremost
  gir1.2-gtk-3.0
  gnuradio
  gobuster
  libgmp-dev
  libssl-dev
  libimage-exiftool-perl
  python3-dev
  nmap
  pari-gp
  patchelf
  qemu-system-arm
  qemu-system-x86
  qemu-user
  ripgrep
  skopeo
  sleuthkit
  socat
  steghide
  stegseek
  upx-ucl
  yara
  zlib1g-dev
)

PIP_TOOLS=(
  objection
  halmos
  garak
  urh
)

PYTHON_MODULE_TOOLS=(
  cysignals
  fpylll
  sigmf
  chipwhisperer
  yara-python
  volatility3
)

PIPX_TOOLS=(
)

GO_TOOLS=(
)

NPM_TOOLS=(
)

CARGO_TOOLS=()

DOTNET_TOOLS=(
  "ilspycmd|ilspycmd"
)

REQUIRED_EXTERNAL_TOOLS=(
  "magma|team deep profile required; commercial CAS, install under a valid license and expose the magma command"
  "yafu|team deep profile required after local managed install failures; install an approved external release or source build and expose yafu on PATH"
  "msieve|team deep profile required after local managed install failures; install an approved external release or source build and expose msieve on PATH"
  "XSStrike|team deep profile required; clone https://github.com/s0md3v/XSStrike externally and expose xsstrike on PATH"
  "feroxbuster|team deep profile required after local managed install failures; install an upstream release or Cargo package externally and expose feroxbuster on PATH"
  "phpggc|team deep profile required; clone https://github.com/ambionics/phpggc externally and expose phpggc on PATH"
  "gef-gdb|team deep profile required; create an external wrapper that sources gef.py from an approved checkout"
  "peda-gdb|team deep profile required for legacy writeup parity; create an external wrapper that sources peda.py"
  "keystone-as|team deep profile required; install an OS or package-manager Keystone assembler build"
  "cfr|team deep profile required; download the CFR jar from https://www.benf.org/other/cfr/ and wrap java -jar"
  "procyon|team deep profile required; download Procyon decompiler jars externally and wrap java -jar"
  "rizin|team deep profile required after local managed install failures; install a distro or upstream release externally and expose rizin on PATH"
  "cutter|team deep profile required after local managed install failures; install the GUI/distro release externally and expose cutter on PATH"
  "rz-ghidra|team deep profile required; install with the matching rizin plugin manager for the local rizin version"
  "r2ghidra|team deep profile required; install with r2pm for the local radare2 version"
  "dotnet|team deep profile required for .NET reversing; install the Microsoft .NET SDK package feed appropriate for the host OS"
  "dnspy|team deep profile required; Windows GUI, use dnSpyEx or an approved local copy outside this repo"
  "bulk_extractor|team deep profile required after local managed install failures; install an approved external package or source build and expose bulk_extractor on PATH"
  "zeek|team deep profile required after local managed install failures; install an approved package/feed externally and expose zeek on PATH"
  "NetworkMiner|team deep profile required; GUI, install from the official upstream release outside this repo"
  "oledump|team deep profile required after local managed install failures; install Didier Stevens oledump.py externally and expose oledump.py on PATH"
  "ripgrep-all|team deep profile required after local managed install failures; install a package or Cargo build externally and expose rga on PATH"
  "MobSF|team deep profile required; heavy service, run official Docker or source setup outside this repo"
  "diec|team deep profile required; Detect It Easy CLI/GUI, install the upstream release matching the host platform"
  "pestudio|team deep profile required; Windows GUI, install externally and keep binaries out of Git"
  "peid|team deep profile required for legacy PE triage parity; install externally and keep binaries out of Git"
  "terraform|team deep profile required; install HashiCorp release or distro package and keep provider credentials out of this workspace"
  "gcloud|team deep profile required; install Google Cloud SDK externally and keep cloud credentials out of this workspace"
  "az|team deep profile required; install Azure CLI externally and keep cloud credentials out of this workspace"
  "kubescape|team deep profile required; install upstream release or script externally and expose kubescape on PATH"
  "nerdctl|team deep profile required; install a release matching local containerd outside this repo"
  "baudline|team deep profile required; closed-source signal GUI, install externally and keep binaries out of Git"
)

usage() {
  cat <<'EOF'
Usage: tools/install_advanced_ctf_tools.sh [options]

Installs advanced, target-specific CTF tools into user-local paths:
  - apt: adb, binwalk, exiftool, qemu, GNU Radio, Sleuth Kit, stegseek, web/pwn helpers
  - isolated user venv wrappers: objection, halmos, garak, urh, volatility3, slither, solc-select
  - workspace venv modules: fpylll, sigmf, chipwhisperer, yara-python, volatility3
  - optional deferred installers only when their tool lists are enabled locally
  - source or upstream binary fallbacks for the remaining managed tools with no apt candidate
  - user checkouts/downloads: pwndbg, Ghidra
  - Foundry toolchain: forge, cast, anvil, chisel
  - Cloud/container tools: kubectl, trivy, syft, grype, crane

Options:
  --dry-run             print the install plan without changing the machine
  --skip-apt            skip sudo apt installation
  --skip-ghidra         skip Ghidra release download
  --skip-pwndbg         skip pwndbg checkout/setup
  --skip-garak          skip garak venv install
  --skip-foundry        skip Foundry install
  --skip-pipx           skip pipx tool installs
  --skip-go             skip Go tool installs
  --skip-npm            skip npm global tool installs
  --skip-cargo          skip cargo tool installs
  --skip-dotnet         skip dotnet global tool installs

Run from a terminal with sudo available. Script-managed tools and required
external tools are both part of the team deep profile. Licensed, GUI,
Windows-only, credentialed, service-style, or non-portable tools stay outside
Git and are reported through PATH/version checks by default. Use
--strict-external on team setup when a full workstation parity gate should fail
on external/manual gaps.
EOF
}

DRY_RUN=0
SKIP_APT=0
SKIP_GHIDRA=0
SKIP_PWNDBG=0
SKIP_GARAK=0
SKIP_FOUNDRY=0
SKIP_PIPX=0
SKIP_GO=0
SKIP_NPM=0
SKIP_CARGO=0
SKIP_DOTNET=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --skip-apt) SKIP_APT=1 ;;
    --skip-ghidra) SKIP_GHIDRA=1 ;;
    --skip-pwndbg) SKIP_PWNDBG=1 ;;
    --skip-garak) SKIP_GARAK=1 ;;
    --skip-foundry) SKIP_FOUNDRY=1 ;;
    --skip-pipx) SKIP_PIPX=1 ;;
    --skip-go) SKIP_GO=1 ;;
    --skip-npm) SKIP_NPM=1 ;;
    --skip-cargo) SKIP_CARGO=1 ;;
    --skip-dotnet) SKIP_DOTNET=1 ;;
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

plan_or_run() {
  local label="$1"
  shift
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'DRYRUN %-24s %q' "$label" "$1"
    shift || true
    local arg
    for arg in "$@"; do
      printf ' %q' "$arg"
    done
    printf '\n'
    return 0
  fi
  if "$@"; then
    printf 'OK %-28s\n' "$label"
    return 0
  fi
  printf 'WARN %-26s failed\n' "$label" >&2
  return 0
}

cpu_count() {
  if command -v nproc >/dev/null 2>&1; then
    nproc
  else
    printf '2\n'
  fi
}

warn_fallback_failed() {
  printf 'WARN fallback %s failed\n' "$1" >&2
}

git_checkout() {
  local repo="$1"
  local dest="$2"
  local recursive="${3:-0}"
  if [ ! -d "$dest/.git" ]; then
    if [ "$recursive" -eq 1 ]; then
      git clone --depth 1 --recursive "$repo" "$dest"
    else
      git clone --depth 1 "$repo" "$dest"
    fi
    return
  fi
  git -C "$dest" pull --ff-only
  if [ "$recursive" -eq 1 ]; then
    git -C "$dest" submodule update --init --recursive
  fi
}

install_from_path() {
  local source="$1"
  local target="$2"
  [ -x "$source" ] || return 1
  install -m 0755 "$source" "$target"
}

write_exec_wrapper() {
  local wrapper="$1"
  local target="$2"
  [ -x "$target" ] || return 1
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'DRYRUN wrapper %s -> %s\n' "$wrapper" "$target"
    return 0
  fi
  cat >"$BIN_DIR/$wrapper" <<EOF
#!/usr/bin/env bash
exec "$target" "\$@"
EOF
  chmod +x "$BIN_DIR/$wrapper"
}

write_python_wrapper() {
  local wrapper="$1"
  local target="$2"
  [ -f "$target" ] || return 1
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'DRYRUN wrapper %s -> %s %s\n' "$wrapper" "$PYTHON" "$target"
    return 0
  fi
  cat >"$BIN_DIR/$wrapper" <<EOF
#!/usr/bin/env bash
exec "$PYTHON" "$target" "\$@"
EOF
  chmod +x "$BIN_DIR/$wrapper"
}

install_alias_wrapper() {
  local wrapper="$1"
  shift
  if command -v "$wrapper" >/dev/null 2>&1; then
    return 0
  fi
  local candidate
  local target
  for candidate in "$@"; do
    target="$(command -v "$candidate" 2>/dev/null || true)"
    if [ -n "$target" ] && [ -x "$target" ] && [ "$target" != "$BIN_DIR/$wrapper" ]; then
      write_exec_wrapper "$wrapper" "$target"
      return 0
    fi
  done
  return 0
}

print_install_policy_summary() {
  printf '\n== Advanced install policy ==\n'
  printf 'INFO managed install phases are best-effort; strict-deep preflight is the final managed gate.\n'
  printf 'INFO external/manual tools are reported, not auto-installed; use team --strict-external for full parity.\n'
  if [ "$SKIP_APT" -eq 1 ]; then
    printf 'INFO apt package phase disabled by --skip-apt.\n'
  elif ! command -v apt-get >/dev/null 2>&1; then
    printf 'WARN apt-get unavailable; apt package phase cannot run.\n' >&2
  elif [ "$DRY_RUN" -eq 1 ]; then
    printf 'INFO dry-run prints the apt plan without requiring sudo.\n'
  elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    printf 'INFO apt package phase can use non-interactive sudo.\n'
  elif [ -t 0 ]; then
    printf 'INFO apt package phase may request sudo interactively.\n'
  else
    printf 'WARN sudo non-interactive apt unavailable; apt package phase will be skipped.\n' >&2
    printf 'INFO run from an interactive sudo-capable terminal for apt coverage, or rely on user-local fallbacks.\n'
  fi
}

apt_package_available() {
  local candidate
  candidate="$(apt-cache policy "$1" 2>/dev/null | awk '/Candidate:/ {print $2; exit}')"
  [ -n "$candidate" ] && [ "$candidate" != "(none)" ]
}

install_available_apt_packages() {
  local packages=()
  local package
  for package in "$@"; do
    if apt_package_available "$package"; then
      packages+=("$package")
    else
      echo "WARN apt package unavailable: $package" >&2
    fi
  done
  if [ "${#packages[@]}" -gt 0 ]; then
    plan_or_run "apt install" sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}"
  fi
}

install_apt_tools() {
  if [ "$SKIP_APT" -eq 1 ]; then
    return 0
  fi
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "WARN apt-get unavailable; skipping apt advanced tools" >&2
    return 0
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'DRYRUN apt update sudo apt-get update\n'
  elif sudo -n true 2>/dev/null; then
    if ! sudo apt-get update; then
      echo "WARN apt-get update failed; skipping apt advanced tools" >&2
      return 0
    fi
  elif [ -t 0 ] && sudo -v; then
    if ! sudo apt-get update; then
      echo "WARN apt-get update failed; skipping apt advanced tools" >&2
      return 0
    fi
  else
    echo "WARN sudo non-interactive apt unavailable; skipping apt advanced tools" >&2
    echo "INFO apt-managed tools will rely on user-local fallbacks where configured" >&2
    return 0
  fi
  install_available_apt_packages "${APT_PACKAGES[@]}"
}

install_pip_entry_tool() {
  local name="$1"
  local entry="$2"
  local dest="$OPT_ROOT/$name"
  shift 2
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'DRYRUN pip %-20s %s\n' "$name" "$*"
    return 0
  fi
  "$PYTHON" -m venv "$dest/.venv"
  "$dest/.venv/bin/python" -m pip install -U pip setuptools wheel
  "$dest/.venv/bin/python" -m pip install -U "$@"
  if [ -x "$dest/.venv/bin/$entry" ]; then
    ln -sfn "$dest/.venv/bin/$entry" "$BIN_DIR/$entry"
  fi
}

install_pip_tool() {
  local name="$1"
  shift
  install_pip_entry_tool "$name" "$name" "$@"
}

install_pip_tools() {
  local tool
  for tool in "${PIP_TOOLS[@]}"; do
    if [ "$tool" = "garak" ] && [ "$SKIP_GARAK" -eq 1 ]; then
      continue
    fi
    install_pip_tool "$tool" "$tool" || true
  done
  install_pip_entry_tool volatility3 vol volatility3 || true
  install_pip_entry_tool slither slither slither-analyzer || true
}

install_workspace_python_modules() {
  if [ ! -x "$VENV_PYTHON" ]; then
    echo "WARN workspace venv python missing; skipping advanced Python modules" >&2
    return 0
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'DRYRUN workspace python modules %s\n' "${PYTHON_MODULE_TOOLS[*]}"
    return 0
  fi
  "$VENV_PYTHON" -m pip install -U "${PYTHON_MODULE_TOOLS[@]}" || true
}

install_solc_select() {
  if command -v solc >/dev/null 2>&1; then
    return 0
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'DRYRUN solc-select install latest\n'
    return 0
  fi
  if ! install_pip_entry_tool solc-select solc-select solc-select; then
    echo "WARN solc-select install failed" >&2
    return 0
  fi
  if [ -x "$OPT_ROOT/solc-select/.venv/bin/solc" ]; then
    ln -sfn "$OPT_ROOT/solc-select/.venv/bin/solc" "$BIN_DIR/solc"
  fi
  plan_or_run "solc latest" "$BIN_DIR/solc-select" install latest
  plan_or_run "solc use latest" "$BIN_DIR/solc-select" use latest
}

install_pwndbg() {
  if [ "$SKIP_PWNDBG" -eq 1 ]; then
    return 0
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'DRYRUN pwndbg checkout/setup %s\n' "$OPT_ROOT/pwndbg"
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
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'DRYRUN ghidra latest release download into %s\n' "$OPT_ROOT"
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
  local target
  target="$(command -v gnuradio-companion 2>/dev/null || true)"
  if [ -z "$target" ] && [ -x /usr/bin/gnuradio-companion ]; then
    target="/usr/bin/gnuradio-companion"
  fi
  if [ -z "$target" ]; then
    return 0
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'DRYRUN wrapper gnuradio-companion-clean -> %s\n' "$target"
    return 0
  fi
  cat >"$BIN_DIR/gnuradio-companion-clean" <<EOF
#!/usr/bin/env bash
export PYTHONNOUSERSITE=1
unset PYTHONPATH
exec "$target" "\$@"
EOF
  chmod +x "$BIN_DIR/gnuradio-companion-clean"
}

install_upx_wrapper() {
  install_alias_wrapper upx upx-ucl
}

install_name_mismatch_wrappers() {
  install_upx_wrapper
  install_alias_wrapper cado-nfs.py cado-nfs
  install_alias_wrapper pdfid.py pdfid
  install_alias_wrapper pdf-parser.py pdf-parser
  install_alias_wrapper qemu-x86_64 qemu-x86_64-static
  install_alias_wrapper qemu-aarch64 qemu-aarch64-static
}

install_foundry() {
  if [ "$SKIP_FOUNDRY" -eq 1 ]; then
    return 0
  fi
  if command -v forge >/dev/null 2>&1 && command -v cast >/dev/null 2>&1 \
    && command -v anvil >/dev/null 2>&1 && command -v chisel >/dev/null 2>&1; then
    return 0
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'DRYRUN foundry install foundryup\n'
    return 0
  fi
  curl -L https://foundry.paradigm.xyz | bash
  "$HOME/.foundry/bin/foundryup"
}

linux_arch() {
  case "$(uname -m)" in
    x86_64|amd64) printf 'amd64\n' ;;
    aarch64|arm64) printf 'arm64\n' ;;
    *)
      echo "Unsupported architecture: $(uname -m)" >&2
      return 1
      ;;
  esac
}

crane_arch() {
  case "$(uname -m)" in
    x86_64|amd64) printf 'x86_64\n' ;;
    aarch64|arm64) printf 'arm64\n' ;;
    *)
      echo "Unsupported architecture: $(uname -m)" >&2
      return 1
      ;;
  esac
}

install_minikube_binary_fallback() {
  if command -v minikube >/dev/null 2>&1; then
    return 0
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'DRYRUN fallback minikube upstream binary\n'
    return 0
  fi
  local arch
  local dest
  arch="$(linux_arch)" || return 1
  dest="$ROOT/.cache/tools/minikube-linux-$arch"
  curl -L "https://storage.googleapis.com/minikube/releases/latest/minikube-linux-$arch" -o "$dest"
  install -m 0755 "$dest" "$BIN_DIR/minikube"
}

install_terragrunt_binary_fallback() {
  if command -v terragrunt >/dev/null 2>&1; then
    return 0
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'DRYRUN fallback terragrunt upstream binary\n'
    return 0
  fi
  local arch
  local dest
  arch="$(linux_arch)" || return 1
  dest="$ROOT/.cache/tools/terragrunt_linux_$arch"
  curl -L "https://github.com/gruntwork-io/terragrunt/releases/latest/download/terragrunt_linux_$arch" -o "$dest"
  install -m 0755 "$dest" "$BIN_DIR/terragrunt"
}

install_radamsa_fallback() {
  if command -v radamsa >/dev/null 2>&1; then
    return 0
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'DRYRUN fallback radamsa source build %s\n' "$OPT_ROOT/radamsa"
    return 0
  fi
  local dest="$OPT_ROOT/radamsa"
  git_checkout https://gitlab.com/akihe/radamsa.git "$dest"
  make -C "$dest" -j"$(cpu_count)"
  install_from_path "$dest/bin/radamsa" "$BIN_DIR/radamsa"
}

install_cado_nfs_fallback() {
  if command -v cado-nfs.py >/dev/null 2>&1; then
    return 0
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'DRYRUN fallback cado-nfs source checkout %s\n' "$OPT_ROOT/cado-nfs"
    return 0
  fi
  local dest="$OPT_ROOT/cado-nfs"
  git_checkout https://gitlab.inria.fr/cado-nfs/cado-nfs.git "$dest"
  if [ -f "$dest/cado-nfs.py" ]; then
    chmod +x "$dest/cado-nfs.py"
    write_exec_wrapper cado-nfs.py "$dest/cado-nfs.py"
  else
    return 1
  fi
}

install_didier_stevens_fallback() {
  if command -v pdfid.py >/dev/null 2>&1 && command -v pdf-parser.py >/dev/null 2>&1; then
    return 0
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'DRYRUN fallback didier-stevens scripts %s\n' "$OPT_ROOT/didier-stevens"
    return 0
  fi
  local dest="$OPT_ROOT/didier-stevens"
  local script
  mkdir -p "$dest"
  for script in pdfid.py pdf-parser.py; do
    if [ ! -s "$dest/$script" ]; then
      curl -fsSL "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/$script" \
        -o "$dest/$script"
    fi
    chmod +x "$dest/$script"
    write_python_wrapper "$script" "$dest/$script"
  done
}

run_fallback() {
  local label="$1"
  shift
  if "$@"; then
    return 0
  fi
  warn_fallback_failed "$label"
  return 0
}

install_managed_fallbacks() {
  run_fallback minikube install_minikube_binary_fallback
  run_fallback terragrunt install_terragrunt_binary_fallback
  run_fallback radamsa install_radamsa_fallback
  run_fallback cado-nfs install_cado_nfs_fallback
  run_fallback didier-stevens install_didier_stevens_fallback
}

install_kubectl() {
  if command -v kubectl >/dev/null 2>&1; then
    return 0
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'DRYRUN kubectl latest stable download\n'
    return 0
  fi
  local arch
  local version
  local dest
  arch="$(linux_arch)"
  version="$(curl -L -s https://dl.k8s.io/release/stable.txt)"
  dest="$ROOT/.cache/tools/kubectl-$version-$arch"
  curl -L "https://dl.k8s.io/release/$version/bin/linux/$arch/kubectl" -o "$dest"
  install -m 0755 "$dest" "$BIN_DIR/kubectl"
}

install_trivy() {
  if command -v trivy >/dev/null 2>&1; then
    return 0
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'DRYRUN trivy install script\n'
    return 0
  fi
  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b "$BIN_DIR"
}

install_syft() {
  if command -v syft >/dev/null 2>&1; then
    return 0
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'DRYRUN syft install script\n'
    return 0
  fi
  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sh -s -- -b "$BIN_DIR"
}

install_grype() {
  if command -v grype >/dev/null 2>&1; then
    return 0
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'DRYRUN grype install script\n'
    return 0
  fi
  curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
    | sh -s -- -b "$BIN_DIR"
}

install_crane() {
  if command -v crane >/dev/null 2>&1; then
    return 0
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'DRYRUN crane latest release download\n'
    return 0
  fi
  local arch
  local archive
  local extract_dir
  arch="$(crane_arch)"
  archive="$ROOT/.cache/tools/go-containerregistry_Linux_$arch.tar.gz"
  extract_dir="$ROOT/.cache/tools/go-containerregistry_Linux_$arch"
  curl -L \
    "https://github.com/google/go-containerregistry/releases/latest/download/go-containerregistry_Linux_$arch.tar.gz" \
    -o "$archive"
  rm -rf "$extract_dir"
  mkdir -p "$extract_dir"
  tar -xzf "$archive" -C "$extract_dir"
  install -m 0755 "$extract_dir/crane" "$BIN_DIR/crane"
}

install_cloud_container_tools() {
  install_kubectl
  install_trivy
  install_syft
  install_grype
  install_crane
}

install_pipx_tools() {
  if [ "$SKIP_PIPX" -eq 1 ]; then
    return 0
  fi
  if [ "${#PIPX_TOOLS[@]}" -eq 0 ]; then
    return 0
  fi
  if ! command -v pipx >/dev/null 2>&1; then
    echo "WARN pipx unavailable; skipping pipx advanced tools" >&2
    return 0
  fi
  local spec
  local command_name
  local package
  local entry
  for spec in "${PIPX_TOOLS[@]}"; do
    IFS='|' read -r command_name package entry <<<"$spec"
    if command -v "$entry" >/dev/null 2>&1; then
      continue
    fi
    plan_or_run "pipx $command_name" pipx install --include-deps --force "$package"
  done
}

install_go_tools() {
  if [ "$SKIP_GO" -eq 1 ]; then
    return 0
  fi
  if [ "${#GO_TOOLS[@]}" -eq 0 ]; then
    return 0
  fi
  if ! command -v go >/dev/null 2>&1; then
    echo "WARN go unavailable; skipping Go advanced tools" >&2
    return 0
  fi
  local spec
  local command_name
  local package
  for spec in "${GO_TOOLS[@]}"; do
    IFS='|' read -r command_name package <<<"$spec"
    if command -v "$command_name" >/dev/null 2>&1; then
      continue
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
      printf 'DRYRUN go %-22s GOBIN=%q go install %q\n' "$command_name" "$BIN_DIR" "$package"
      continue
    fi
    if GOBIN="$BIN_DIR" go install "$package"; then
      printf 'OK go %-24s\n' "$command_name"
    else
      printf 'WARN go %-22s failed\n' "$command_name" >&2
    fi
  done
}

install_npm_tools() {
  if [ "$SKIP_NPM" -eq 1 ]; then
    return 0
  fi
  if [ "${#NPM_TOOLS[@]}" -eq 0 ]; then
    return 0
  fi
  if ! command -v npm >/dev/null 2>&1; then
    echo "WARN npm unavailable; skipping npm advanced tools" >&2
    return 0
  fi
  local spec
  local command_name
  local package
  for spec in "${NPM_TOOLS[@]}"; do
    IFS='|' read -r command_name package <<<"$spec"
    if command -v "$command_name" >/dev/null 2>&1; then
      continue
    fi
    plan_or_run "npm $command_name" npm install -g "$package"
  done
}

install_cargo_tools() {
  if [ "$SKIP_CARGO" -eq 1 ]; then
    return 0
  fi
  if [ "${#CARGO_TOOLS[@]}" -eq 0 ]; then
    return 0
  fi
  if ! command -v cargo >/dev/null 2>&1; then
    echo "WARN cargo unavailable; skipping cargo advanced tools" >&2
    return 0
  fi
  local spec
  local command_name
  local crate
  for spec in "${CARGO_TOOLS[@]}"; do
    IFS='|' read -r command_name crate <<<"$spec"
    if command -v "$command_name" >/dev/null 2>&1; then
      continue
    fi
    plan_or_run "cargo $command_name" cargo install "$crate"
  done
}

install_dotnet_tools() {
  if [ "$SKIP_DOTNET" -eq 1 ]; then
    return 0
  fi
  if [ "${#DOTNET_TOOLS[@]}" -eq 0 ]; then
    return 0
  fi
  if ! command -v dotnet >/dev/null 2>&1; then
    echo "INFO dotnet unavailable; skipping dotnet-dependent advanced tools"
    return 0
  fi
  local spec
  local command_name
  local package
  for spec in "${DOTNET_TOOLS[@]}"; do
    IFS='|' read -r command_name package <<<"$spec"
    if command -v "$command_name" >/dev/null 2>&1; then
      continue
    fi
    plan_or_run "dotnet $command_name" dotnet tool install --global "$package"
  done
}

print_required_external_tools() {
  local spec
  local tool
  local reason
  printf '\nRequired external tools not portably auto-installed by this script:\n'
  printf 'These remain team-standard tools, but default strict deep setup reports them separately.\n'
  printf 'Use --strict-external in team setup to fail on PATH/version gaps.\n'
  for spec in "${REQUIRED_EXTERNAL_TOOLS[@]}"; do
    IFS='|' read -r tool reason <<<"$spec"
    printf '  - %s: %s\n' "$tool" "$reason"
  done
}

print_install_policy_summary
install_apt_tools || true
install_pip_tools || true
install_workspace_python_modules || true
install_pipx_tools || true
install_go_tools || true
install_npm_tools || true
install_cargo_tools || true
install_dotnet_tools || true
install_managed_fallbacks || true
install_solc_select || true
install_pwndbg || true
ROOT="$ROOT" OPT_ROOT="$OPT_ROOT" BIN_DIR="$BIN_DIR" install_ghidra || true
install_gnuradio_wrapper || true
install_name_mismatch_wrappers || true
install_foundry || true
install_cloud_container_tools || true
print_required_external_tools

if [ "$DRY_RUN" -eq 1 ]; then
  status_line="Advanced CTF tool install plan generated."
else
  status_line="Advanced CTF tools installed or reported with warnings."
fi

cat <<EOF

$status_line
Run:
  . .codex/env.sh
  python3 tools/preflight_check.py --strict-deep --category pwn
  python3 tools/preflight_check.py --strict-deep --category rev
  python3 tools/preflight_check.py --strict-deep --category crypto
  python3 tools/preflight_check.py --strict-deep --category forensics
  python3 tools/preflight_check.py --strict-deep --category stego
  python3 tools/preflight_check.py --strict-deep --category mobile
  python3 tools/preflight_check.py --strict-deep --category malware
  python3 tools/preflight_check.py --strict-deep --category web3
  python3 tools/preflight_check.py --strict-deep --category web
  python3 tools/preflight_check.py --strict-deep --category cloud
  python3 tools/preflight_check.py --strict-deep --category container
  python3 tools/preflight_check.py --strict-deep --category ai-ml
  python3 tools/preflight_check.py --strict-deep --category hardware-rf
  python3 tools/preflight_check.py --strict-deep --category side-channel
  python3 tools/preflight_check.py --strict-deep --category misc
  python3 tools/preflight_check.py --strict-deep --category programming
  python3 tools/preflight_check.py --strict-deep --external-policy fail --category rev
EOF
