#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

/opt/ctf-os/install/binary-runtime.sh

PWNINIT_VERSION=3.3.1
PWNINIT_SHA256=1b72653be59f8f13ea934d1153e8d845eac0dbac62a8c4d9dc4a25577f009362
PWNDBG_VERSION=2026.02.18
PWNDBG_SHA256=eeb93972d7910bf8233abf296b00577efb7137d94655502985566a328e5cecce
SECCOMP_TOOLS_VERSION=1.6.2

apt_install \
  gdb gdb-multiarch patchelf checksec strace ltrace libc6-dbg libc6-dev \
  qemu-system-x86 qemu-system-arm qemu-system-misc qemu-utils \
  binfmt-support cpio busybox-static squashfs-tools pahole dwarves seccomp libseccomp-dev nasm \
  musl-tools
pip_install_locked /opt/ctf-os/requirements-lock/pwn.txt
gem install one_gadget --version 1.10.0 --no-document
gem install seccomp-tools --version "$SECCOMP_TOOLS_VERSION" --no-document

download_sha256 \
  "https://github.com/io12/pwninit/releases/download/${PWNINIT_VERSION}/pwninit" \
  /usr/local/bin/pwninit "$PWNINIT_SHA256"
chmod 0755 /usr/local/bin/pwninit

download_sha256 \
  "https://github.com/pwndbg/pwndbg/releases/download/${PWNDBG_VERSION}/pwndbg_${PWNDBG_VERSION}_x86_64-portable.tar.xz" \
  /tmp/pwndbg.tar.xz "$PWNDBG_SHA256"
tar -xJf /tmp/pwndbg.tar.xz -C /opt
ln -s /opt/pwndbg/bin/pwndbg /usr/local/bin/pwndbg
rm -f /tmp/pwndbg.tar.xz

for command in gdb gdb-multiarch pwndbg patchelf checksec ROPgadget ropper one_gadget pwninit seccomp-tools musl-gcc qemu-aarch64 qemu-arm qemu-mips qemu-mipsel qemu-riscv64 qemu-system-x86_64 qemu-system-aarch64 cpio; do
  require_command "$command"
done
for module in pwn angr angrop unicorn capstone keystone z3; do require_import "$module"; done
python3 -c 'import angr, angrop; assert angr.Project and angrop'
pwndbg --batch -q \
  -ex 'pi import pwndbg; print(pwndbg.__version__)' \
  -ex quit | grep -Fx "$PWNDBG_VERSION"
pwninit --version
seccomp-tools --version
musl-gcc --version
/usr/local/bin/ctf-os-binary-runtime-smoke
