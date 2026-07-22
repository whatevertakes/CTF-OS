#!/usr/bin/env bash
set -Eeuo pipefail

smoke_root="$(mktemp -d /work/binary-analysis-smoke.XXXXXX)"
sample_name="ctf-os-binary-smoke-$$"
cleanup() {
  rm -rf -- "$smoke_root"
  rm -f -- "/artifacts/${sample_name}.ghidra.c" "/artifacts/${sample_name}.ghidra.log"
}
trap cleanup EXIT
cat >"$smoke_root/elf.c" <<'EOF'
#include <stdio.h>
int main(void) { puts("CTF_OS_BINARY_ANALYSIS_OK"); return 0; }
EOF
gcc -O0 "$smoke_root/elf.c" -o "$smoke_root/$sample_name"
ctf-ghidra-headless "$smoke_root/$sample_name" 180 >/dev/null
grep -q 'main' "/artifacts/${sample_name}.ghidra.c"
capa -q -r /opt/capa-rules "$smoke_root/$sample_name" >/dev/null

cat >"$smoke_root/pe.c" <<'EOF'
void mainCRTStartup(void) { volatile int value = 7; (void)value; }
EOF
clang --target=x86_64-w64-windows-gnu -fuse-ld=lld -nostdlib \
  -Wl,-entry,mainCRTStartup -Wl,-subsystem,console \
  "$smoke_root/pe.c" -o "$smoke_root/sample.exe"
file "$smoke_root/sample.exe" | grep -q 'PE32+'
capa -q -r /opt/capa-rules "$smoke_root/sample.exe" >/dev/null
python3 -c 'import frida,pyghidra'
frida-ps --version >/dev/null
echo CTF_OS_BINARY_ANALYSIS_SMOKE_OK
