#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

apt_install \
  gdb gdb-multiarch patchelf checksec strace ltrace libc6-dbg libc6-dev \
  qemu-user qemu-user-static qemu-system-x86 qemu-system-arm qemu-system-misc qemu-utils \
  binfmt-support cpio busybox-static squashfs-tools pahole dwarves seccomp libseccomp-dev nasm
pip_install -r /opt/ctf-os/requirements/pwn.txt
gem install one_gadget --version 1.10.0 --no-document

for command in gdb gdb-multiarch patchelf checksec ROPgadget ropper one_gadget qemu-aarch64 qemu-mips qemu-riscv64 qemu-system-x86_64 qemu-system-aarch64 cpio; do
  require_command "$command"
done
for module in pwn angr unicorn capstone keystone z3; do require_import "$module"; done
