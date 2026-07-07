#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

# shellcheck disable=SC1091
. .codex/env.sh

run_optional() {
  local label="$1"
  local output
  shift
  printf '%-24s ' "$label"
  output="$("$@" 2>&1 | sed '/^[[:space:]]*$/d' | head -1 || true)"
  if [ -n "$output" ]; then
    printf '%s\n' "$output"
  else
    printf 'OK\n'
  fi
}

show_path() {
  local command="$1"
  local path
  if path="$(command -v "$command")"; then
    printf '%-24s %s\n' "path $command" "$path"
  else
    printf '%-24s MISSING\n' "path $command"
  fi
}

show_r2mcp_path() {
  local candidate
  for candidate in \
    "${R2MCP_BIN:-}" \
    "$(command -v r2mcp 2>/dev/null || true)" \
    "$HOME/.local/bin/r2mcp" \
    "$HOME/.local/share/radare2/prefix/bin/r2mcp" \
    "/usr/local/bin/r2mcp" \
    "/usr/bin/r2mcp"; do
    if [ -n "$candidate" ] && [ -x "$candidate" ]; then
      printf '%-24s %s\n' "path r2mcp" "$candidate"
      return
    fi
  done
  printf '%-24s MISSING\n' "path r2mcp"
}

echo "== workspace =="
pwd
echo "CTF_WORKSPACE_ROOT=$CTF_WORKSPACE_ROOT"

echo "== managed paths =="
show_path rg
show_path binwalk
show_path exiftool
show_path nmap
show_path socat
show_path angr-mcp
show_path checksec
show_path ROPgadget
show_path ropper
show_path r2
show_r2mcp_path
show_path npx
show_path mcp
show_path fastmcp
show_path mcp-proxy
show_path mcp-reverse-proxy
show_path RsaCtfTool
show_path arjun
show_path flask-unsign
show_path floss
show_path frida
show_path shodan
show_path stegolsb
show_path zsteg
show_path wafw00f
show_path pwninit
show_path nuclei
show_path katana
show_path feroxbuster
show_path amass
show_path subfinder
show_path gau
show_path waybackurls
show_path hakrawler
show_path dalfox
show_path commix
show_path interactsh-client
show_path dnsx
show_path naabu
show_path http
show_path valgrind
show_path afl-fuzz
show_path honggfuzz
show_path radamsa
show_path heaptrack
show_path capa
show_path rizin
show_path ilspycmd
show_path monodis
show_path llvm-objdump
show_path yafu
show_path msieve
show_path cado-nfs.py
show_path gap
show_path bulk_extractor
show_path zeek
show_path pdfid.py
show_path pdf-parser.py
show_path oledump.py
show_path outguess
show_path exiv2
show_path rga
show_path apkid
show_path apksigner
show_path mobsfscan
show_path helm
show_path k9s
show_path kind
show_path minikube
show_path podman
show_path cosign
show_path dive
show_path regctl
show_path oras
show_path aws
show_path terragrunt
show_path checkov
show_path kube-linter
show_path kube-score
show_path promptfoo
show_path inspectrum
show_path sigmf_validate
show_path rtl_433
show_path rtl_sdr
show_path hackrf_info
show_path sigrok-cli
show_path pulseview
show_path openocd
show_path arm-none-eabi-gcc
show_path arm-none-eabi-objdump
show_path chipwhisperer
show_path audacity
show_path qemu-x86_64
show_path qemu-aarch64
show_path qemu-system-x86_64
show_path qemu-system-arm
show_path qemu-system-aarch64

echo "== external manual paths =="
show_path magma
show_path xsstrike
show_path phpggc
show_path gef-gdb
show_path peda-gdb
show_path keystone-as
show_path cfr
show_path procyon
show_path rz-ghidra
show_path r2ghidra
show_path dotnet
show_path dnspy
show_path NetworkMiner
show_path mobsf
show_path diec
show_path pestudio
show_path peid
show_path gcloud
show_path az
show_path terraform
show_path kubescape
show_path nerdctl
show_path baudline

echo "== core =="
run_optional git git --version
run_optional rg rg --version
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
    "fastmcp",
    "mcp",
    "mcp-proxy",
    "arjun",
    "flask-unsign",
    "flare-floss",
    "frida-tools",
    "shodan",
    "stego-lsb",
    "wafw00f",
]:
    try:
        print(f"{package}=={md.version(package)}")
    except md.PackageNotFoundError:
        print(f"MISSING {package}")
PY

echo "== pwn/rev tools =="
run_optional checksec checksec --version
run_optional ROPgadget env PYTHONWARNINGS=ignore::SyntaxWarning ROPgadget --version
run_optional ropper env PYTHONWARNINGS=ignore::SyntaxWarning ropper --version
run_optional one_gadget one_gadget --version
run_optional seccomp-tools seccomp-tools --version
run_optional r2 r2 -v
if [ -x .codex/bin/r2mcp-codex.sh ]; then
  printf '%-24s %s\n' "r2mcp-wrapper" ".codex/bin/r2mcp-codex.sh configured"
else
  printf '%-24s MISSING\n' "r2mcp-wrapper"
fi
if [ -x .codex/bin/playwright-mcp-codex.sh ]; then
  printf '%-24s %s\n' "playwright-wrapper" "$(.codex/bin/playwright-mcp-codex.sh --print-browser 2>/dev/null || printf 'browser missing')"
else
  printf '%-24s MISSING\n' "playwright-wrapper"
fi
run_optional pwninit pwninit --version

echo "== mobile/forensics/math =="
run_optional binwalk binwalk --help
run_optional exiftool exiftool -ver
run_optional jadx jadx --version
run_optional apktool apktool --version
run_optional frida frida --version
run_optional frida-ps frida-ps --version
run_optional floss floss --version
run_optional stegolsb stegolsb --version
run_optional zsteg zsteg --help
run_optional sage sage --version
run_optional tshark tshark --version

echo "== web/crypto cli =="
run_optional nmap nmap --version
run_optional socat socat -V
run_optional RsaCtfTool RsaCtfTool --help
run_optional arjun arjun -h
run_optional flask-unsign flask-unsign --version
run_optional shodan env PYTHONWARNINGS=ignore::UserWarning shodan version
run_optional wafw00f wafw00f --version
run_optional nuclei nuclei -version
run_optional katana katana -version
run_optional feroxbuster feroxbuster --version
run_optional subfinder subfinder -version
run_optional gau gau --version
run_optional dalfox dalfox version
run_optional dnsx dnsx -version
run_optional naabu naabu -version
run_optional httpie http --version

echo "== mcp utility cli =="
run_optional mcp mcp version
run_optional fastmcp fastmcp --version
run_optional mcp-proxy mcp-proxy --version
run_optional mcp-reverse-proxy mcp-reverse-proxy --version

echo "== advanced category cli =="
run_optional valgrind valgrind --version
run_optional radamsa radamsa --version
run_optional heaptrack heaptrack --version
run_optional capa capa --version
run_optional rizin rizin -v
run_optional llvm-objdump llvm-objdump --version
run_optional bulk_extractor bulk_extractor -V
run_optional zeek zeek --version
run_optional exiv2 exiv2 --version
run_optional apkid apkid --version
run_optional mobsfscan mobsfscan --version
run_optional helm helm version --short
run_optional kind kind version
run_optional podman podman --version
run_optional cosign cosign version
run_optional regctl regctl version
run_optional oras oras version
run_optional aws aws --version
run_optional checkov checkov --version
run_optional promptfoo promptfoo --version
run_optional sigrok-cli sigrok-cli --version
run_optional openocd openocd --version
run_optional arm-none-eabi-gcc arm-none-eabi-gcc --version

echo "== mcp =="
codex mcp list

echo "== final checks =="
python3 tools/preflight_check.py --strict-optional | tail -5
python3 tools/check_team_parity.py
