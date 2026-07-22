#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

# Debian 12 cross GCC packages conflict with the gcc-multilib metapackage, but
# coexist with its versioned implementation. gcc-12-multilib preserves gcc -m32.
apt_install \
  gcc-12-multilib libc6-dev-i386 \
  gcc-aarch64-linux-gnu gcc-arm-linux-gnueabihf \
  gcc-mipsel-linux-gnu gcc-riscv64-linux-gnu \
  binutils-aarch64-linux-gnu binutils-arm-linux-gnueabihf \
  binutils-mipsel-linux-gnu binutils-riscv64-linux-gnu \
  libc6-arm64-cross libc6-dev-arm64-cross \
  libc6-armhf-cross libc6-dev-armhf-cross \
  libc6-mipsel-cross libc6-dev-mipsel-cross \
  libc6-riscv64-cross libc6-dev-riscv64-cross \
  qemu-user qemu-user-static

for command in \
  aarch64-linux-gnu-gcc arm-linux-gnueabihf-gcc \
  mipsel-linux-gnu-gcc riscv64-linux-gnu-gcc \
  qemu-aarch64 qemu-arm qemu-mips qemu-mipsel qemu-riscv64; do
  require_command "$command"
done

for sysroot in \
  /usr/aarch64-linux-gnu /usr/arm-linux-gnueabihf \
  /usr/mipsel-linux-gnu /usr/riscv64-linux-gnu; do
  [[ -d "$sysroot" ]] || { echo "foreign sysroot missing: $sysroot" >&2; exit 1; }
done

/usr/local/bin/ctf-os-binary-runtime-smoke
