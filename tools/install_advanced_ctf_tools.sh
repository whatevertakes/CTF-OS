#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"
VENV_PYTHON="$ROOT/.venv/bin/python"
OPT_ROOT="${CTF_ADVANCED_TOOLS_ROOT:-$HOME/.local/opt/ctf-tools}"
BIN_DIR="$HOME/.local/bin"

APT_PACKAGES=(
  adb
  afl++
  afl
  amass
  apkid
  apksigner
  audacity
  binwalk
  bulk-extractor
  cado-nfs
  cargo
  checkov
  cmake
  cutter
  dnsutils
  emscripten
  exiv2
  feroxbuster
  ffuf
  fplll-tools
  foremost
  gap
  gcc-arm-none-eabi
  gir1.2-gtk-3.0
  gnuradio
  gobuster
  hackrf
  heaptrack
  honggfuzz
  httpie
  inspectrum
  llvm
  llvm-dev
  mono-devel
  mono-utils
  libimage-exiftool-perl
  minikube
  msieve
  openocd
  outguess
  php-cli
  php-curl
  podman
  pulseview
  nmap
  pari-gp
  patchelf
  qemu-system-arm
  qemu-system-x86
  qemu-user
  radamsa
  ripgrep
  ripgrep-all
  rizin
  rtl-433
  rtl-sdr
  sigrok-cli
  skopeo
  sleuthkit
  socat
  steghide
  stegseek
  upx-ucl
  valgrind
  yara
  yafu
  zeek
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
  "apkid|apkid|apkid"
  "aws|awscli|awscli"
  "capa|flare-capa|capa"
  "checkov|checkov|checkov"
  "commix|commix|commix"
  "http|httpie|httpie"
  "mobsfscan|mobsfscan|mobsfscan"
)

GO_TOOLS=(
  "nuclei|github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "katana|github.com/projectdiscovery/katana/cmd/katana@latest"
  "subfinder|github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "gau|github.com/lc/gau/v2/cmd/gau@latest"
  "waybackurls|github.com/tomnomnom/waybackurls@latest"
  "hakrawler|github.com/hakluke/hakrawler@latest"
  "dalfox|github.com/hahwul/dalfox/v2@latest"
  "interactsh-client|github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
  "dnsx|github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "naabu|github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "amass|github.com/owasp-amass/amass/v4/...@master"
  "helm|helm.sh/helm/v3/cmd/helm@latest"
  "k9s|github.com/derailed/k9s@latest"
  "kind|sigs.k8s.io/kind@latest"
  "minikube|k8s.io/minikube/cmd/minikube@latest"
  "cosign|github.com/sigstore/cosign/v2/cmd/cosign@latest"
  "dive|github.com/wagoodman/dive@latest"
  "regctl|github.com/regclient/regclient/cmd/regctl@latest"
  "oras|oras.land/oras/cmd/oras@latest"
  "terragrunt|github.com/gruntwork-io/terragrunt@latest"
  "kube-linter|golang.stackrox.io/kube-linter/cmd/kube-linter@latest"
  "kube-score|github.com/zegl/kube-score/cmd/kube-score@latest"
)

NPM_TOOLS=(
  "promptfoo|promptfoo@latest"
)

CARGO_TOOLS=(
  "feroxbuster|feroxbuster"
)

DOTNET_TOOLS=(
  "ilspycmd|ilspycmd"
)

MANUAL_TOOLS=(
  "magma|commercial CAS; install under a valid license and expose the magma command"
  "XSStrike|clone https://github.com/s0md3v/XSStrike when an XSS challenge needs context-aware payload generation"
  "phpggc|clone https://github.com/ambionics/phpggc and expose phpggc after PHP is installed"
  "gef|source gef.py from an explicit gef-gdb wrapper when a challenge needs this GDB UI"
  "peda|source peda.py from an explicit peda-gdb wrapper only for legacy writeup compatibility"
  "keystone-as|install an OS/package-manager Keystone assembler build when shellcode assembly needs it"
  "cfr|download the CFR jar from https://www.benf.org/other/cfr/ and wrap java -jar"
  "procyon|download Procyon decompiler jars and wrap java -jar"
  "rz-ghidra|install with the matching rizin plugin manager for the local rizin version"
  "r2ghidra|install with r2pm for the local radare2 version"
  "dotnet|install the Microsoft .NET SDK package feed appropriate for the host OS"
  "dnspy|Windows GUI; use dnSpyEx or an approved local copy"
  "NetworkMiner|GUI; install from the official upstream release when packet extraction needs it"
  "MobSF|heavy service; run official Docker or source setup only for mobile challenges"
  "diec|Detect It Easy CLI/GUI; install the upstream release matching the host platform"
  "pestudio|Windows GUI; install externally if PE triage requires it"
  "peid|legacy Windows GUI; install externally only for compatibility with old writeups"
  "terraform|install HashiCorp release or distro package; keep provider credentials out of this workspace"
  "gcloud|install Google Cloud SDK externally when an owned cloud challenge requires it"
  "az|install Azure CLI externally when an owned cloud challenge requires it"
  "kubescape|install upstream release or script when Kubernetes posture checks require it"
  "nerdctl|install a release matching local containerd when Docker-compatible containerd work is needed"
  "baudline|closed-source signal GUI; install externally if a signal challenge requires it"
)

usage() {
  cat <<'EOF'
Usage: tools/install_advanced_ctf_tools.sh [options]

Installs advanced, target-specific CTF tools into user-local paths:
  - apt: adb, binwalk, exiftool, qemu, GNU Radio, Sleuth Kit, stegseek, web/pwn helpers
  - isolated user venv wrappers: objection, halmos, garak, urh, volatility3, slither, solc-select
  - workspace venv modules: fpylll, sigmf, chipwhisperer, yara-python, volatility3
  - pipx tools: apkid, awscli, capa, checkov, commix, httpie, mobsfscan
  - Go tools: nuclei, katana, subfinder, gau, waybackurls, hakrawler, dalfox,
    interactsh-client, dnsx, naabu, helm, k9s, kind, cosign, dive, regctl, oras
  - npm tools: promptfoo
  - cargo/dotnet tools when cargo or dotnet is already present
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

Run from a terminal with sudo available. These tools are intentionally not part
of the default team setup because garak/Ghidra/GNU Radio are large.
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
    echo "WARN sudo unavailable; skipping apt advanced tools" >&2
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
  if [ "$DRY_RUN" -eq 1 ]; then
    printf 'DRYRUN wrapper gnuradio-companion-clean\n'
    return 0
  fi
  cat >"$BIN_DIR/gnuradio-companion-clean" <<'EOF'
#!/usr/bin/env bash
export PYTHONNOUSERSITE=1
unset PYTHONPATH
exec /usr/bin/gnuradio-companion "$@"
EOF
  chmod +x "$BIN_DIR/gnuradio-companion-clean"
}

install_upx_wrapper() {
  if command -v upx >/dev/null 2>&1; then
    return 0
  fi
  if command -v upx-ucl >/dev/null 2>&1; then
    if [ "$DRY_RUN" -eq 1 ]; then
      printf 'DRYRUN wrapper upx -> upx-ucl\n'
      return 0
    fi
    cat >"$BIN_DIR/upx" <<'EOF'
#!/usr/bin/env bash
exec upx-ucl "$@"
EOF
    chmod +x "$BIN_DIR/upx"
  fi
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
  if ! command -v dotnet >/dev/null 2>&1; then
    echo "WARN dotnet unavailable; skipping dotnet advanced tools" >&2
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

print_manual_tools() {
  local spec
  local tool
  local reason
  printf '\nManual or externally managed tools:\n'
  for spec in "${MANUAL_TOOLS[@]}"; do
    IFS='|' read -r tool reason <<<"$spec"
    printf '  - %s: %s\n' "$tool" "$reason"
  done
}

install_apt_tools || true
install_pip_tools || true
install_workspace_python_modules || true
install_pipx_tools || true
install_go_tools || true
install_npm_tools || true
install_cargo_tools || true
install_dotnet_tools || true
install_solc_select || true
install_pwndbg || true
ROOT="$ROOT" OPT_ROOT="$OPT_ROOT" BIN_DIR="$BIN_DIR" install_ghidra || true
install_gnuradio_wrapper || true
install_upx_wrapper || true
install_foundry || true
install_cloud_container_tools || true
print_manual_tools

if [ "$DRY_RUN" -eq 1 ]; then
  status_line="Advanced CTF tool install plan generated."
else
  status_line="Advanced CTF tools installed or reported with warnings."
fi

cat <<EOF

$status_line
Run:
  . .codex/env.sh
  python3 tools/preflight_check.py --deep --category pwn
  python3 tools/preflight_check.py --deep --category rev
  python3 tools/preflight_check.py --deep --category mobile
  python3 tools/preflight_check.py --deep --category web3
  python3 tools/preflight_check.py --deep --category web
  python3 tools/preflight_check.py --deep --category cloud
  python3 tools/preflight_check.py --deep --category container
  python3 tools/preflight_check.py --deep --category ai-ml
  python3 tools/preflight_check.py --deep --category hardware-rf
  python3 tools/preflight_check.py --deep --category side-channel
EOF
