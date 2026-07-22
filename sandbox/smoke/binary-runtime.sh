#!/usr/bin/env bash
set -Eeuo pipefail

fixture_dir="$(mktemp -d /tmp/ctf-os-binary-runtime.XXXXXX)"
cleanup() { rm -rf -- "$fixture_dir"; }
trap cleanup EXIT

cat >"$fixture_dir/probe.c" <<'EOF'
#include <stdio.h>

int main(void) {
    puts("CTF_OS_QEMU_OK");
    return 0;
}
EOF

check_output() {
  local architecture="$1"
  shift
  local output
  output="$("$@")"
  [[ "$output" == "CTF_OS_QEMU_OK" ]] || {
    echo "$architecture runtime returned unexpected output: $output" >&2
    exit 1
  }
  printf '%s=%s\n' "$architecture" "$output"
}

aarch64-linux-gnu-gcc "$fixture_dir/probe.c" -o "$fixture_dir/aarch64"
arm-linux-gnueabihf-gcc "$fixture_dir/probe.c" -o "$fixture_dir/armhf"
mipsel-linux-gnu-gcc "$fixture_dir/probe.c" -o "$fixture_dir/mipsel"
riscv64-linux-gnu-gcc "$fixture_dir/probe.c" -o "$fixture_dir/riscv64"
gcc -m32 "$fixture_dir/probe.c" -o "$fixture_dir/i386"

for binary in aarch64 armhf mipsel riscv64 i386; do
  file "$fixture_dir/$binary" | grep -q 'dynamically linked'
done

check_output aarch64 qemu-aarch64 -L /usr/aarch64-linux-gnu "$fixture_dir/aarch64"
check_output armhf qemu-arm -L /usr/arm-linux-gnueabihf "$fixture_dir/armhf"
check_output mipsel qemu-mipsel -L /usr/mipsel-linux-gnu "$fixture_dir/mipsel"
check_output riscv64 qemu-riscv64 -L /usr/riscv64-linux-gnu "$fixture_dir/riscv64"
check_output i386 "$fixture_dir/i386"
