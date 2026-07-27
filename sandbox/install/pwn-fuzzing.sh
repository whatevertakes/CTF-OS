#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

AFLPP_VERSION=5.02c
AFLPP_COMMIT=011cd189801830253c66ecd3cd6919ec01b46c34
AFLPP_SHA256=6692be97d77483021e174df408f76ad615828726abfa4bbc003eda78f38ebaf3
QEMUAFL_COMMIT=3f571d0272e6d43c0226a1105c4bd74aab9149b5
QEMUAFL_SHA256=928275fedc0a3277c0e0447cffaa99c2a8b3f191e18276341cf0655a2275cb1e
KEYCODEMAPDB_COMMIT=6119e6e19a050df847418de7babe5166779955e4
KEYCODEMAPDB_SHA256=70b6fae56c4c5b1a8508fea0ed39b6cd96ef887b600d759129f35d5a066a88d5
SOFTFLOAT_COMMIT=b64af41c3276f97f0e181920400ee056b9c88037
SOFTFLOAT_SHA256=faae889814ea6a292f7ca03d9b36e6c7e95bab2a64777804883cc822b8d48757
TESTFLOAT_COMMIT=5a59dcec19327396a011a17fd924aed4fec416b3
TESTFLOAT_SHA256=c1f92abe87764de22f6cf8372d697717d18e7951ceb11b6e12c6767b7d1e3a65
FRIDA_GUM_VERSION=17.9.3
FRIDA_GUM_SHA256=863935f90bebccec6db465beb97354692fc7a2070cb1b40bc27877d3fef2afba
apt_install \
  libglib2.0-dev libpixman-1-dev llvm-dev libclang-rt-dev meson \
  clang-19 llvm-19-dev libclang-rt-19-dev lld-19
download_sha256 \
  "https://codeload.github.com/AFLplusplus/AFLplusplus/tar.gz/${AFLPP_COMMIT}" \
  /tmp/aflpp.tar.gz "$AFLPP_SHA256"
mkdir -p /tmp/aflpp
tar -xzf /tmp/aflpp.tar.gz -C /tmp/aflpp --strip-components=1
download_sha256 \
  "https://codeload.github.com/AFLplusplus/qemuafl/tar.gz/${QEMUAFL_COMMIT}" \
  /tmp/qemuafl.tar.gz "$QEMUAFL_SHA256"
mkdir -p /tmp/aflpp/qemu_mode/qemuafl/.git
tar -xzf /tmp/qemuafl.tar.gz -C /tmp/aflpp/qemu_mode/qemuafl --strip-components=1
download_sha256 \
  "https://gitlab.com/qemu-project/keycodemapdb/-/archive/${KEYCODEMAPDB_COMMIT}/keycodemapdb-${KEYCODEMAPDB_COMMIT}.tar.gz" \
  /tmp/keycodemapdb.tar.gz "$KEYCODEMAPDB_SHA256"
mkdir -p /tmp/aflpp/qemu_mode/qemuafl/ui/keycodemapdb
tar -xzf /tmp/keycodemapdb.tar.gz \
  -C /tmp/aflpp/qemu_mode/qemuafl/ui/keycodemapdb --strip-components=1
for dependency in softfloat testfloat; do
  commit_var="${dependency^^}_COMMIT"
  checksum_var="${dependency^^}_SHA256"
  repository="berkeley-${dependency}-3"
  download_sha256 \
    "https://gitlab.com/qemu-project/${repository}/-/archive/${!commit_var}/${repository}-${!commit_var}.tar.gz" \
    "/tmp/${dependency}.tar.gz" "${!checksum_var}"
  target="/tmp/aflpp/qemu_mode/qemuafl/tests/fp/${repository}"
  mkdir -p "$target"
  tar -xzf "/tmp/${dependency}.tar.gz" -C "$target" --strip-components=1
done
# The pinned release archive intentionally has no Git submodule metadata. Keep
# qemuafl fully offline instead of letting its helper attempt a checkout.
sed -i 's|\./configure \$QEMU_CONF_FLAGS|./configure --with-git-submodules=ignore $QEMU_CONF_FLAGS|' \
  /tmp/aflpp/qemu_mode/build_qemu_support.sh
(cd /tmp/aflpp && LLVM_CONFIG=/usr/bin/llvm-config-19 make -j2 all)
mkdir -p /tmp/aflpp/frida_mode/build/frida
download_sha256 \
  "https://github.com/frida/frida/releases/download/${FRIDA_GUM_VERSION}/frida-gumjs-devkit-${FRIDA_GUM_VERSION}-linux-x86_64.tar.xz" \
  "/tmp/aflpp/frida_mode/build/frida/frida-gumjs-devkit-${FRIDA_GUM_VERSION}-linux-x86_64.tar.xz" \
  "$FRIDA_GUM_SHA256"
(cd /tmp/aflpp && LLVM_CONFIG=/usr/bin/llvm-config-19 make -C frida_mode -j1)
(cd /tmp/aflpp && LLVM_CONFIG=/usr/bin/llvm-config-19 PREFIX=/usr/local make install)
for cpu_target in x86_64 aarch64 arm mips mipsel; do
  rm -rf /tmp/aflpp/qemu_mode/qemuafl/build
  (
    cd /tmp/aflpp/qemu_mode
    NO_CHECKOUT=1 CPU_TARGET="$cpu_target" ./build_qemu_support.sh
  )
  install -m 0755 /tmp/aflpp/afl-qemu-trace \
    "/usr/local/bin/afl-qemu-trace-${cpu_target}"
done
install -m 0755 /usr/local/bin/afl-qemu-trace-x86_64 \
  /usr/local/bin/afl-qemu-trace
install -m 0755 /usr/local/bin/afl-qemu-trace-x86_64 \
  /usr/local/lib/afl/afl-qemu-trace

for command in \
  afl-fuzz afl-showmap afl-clang-fast afl-clang-fast++ afl-qemu-trace \
  afl-cc afl-clang-lto afl-ld-lto afl-analyze afl-whatsup afl-plot \
  clang-19 llvm-config-19; do
  require_command "$command"
done
test -f /usr/local/lib/afl/afl-frida-trace.so
for cpu_target in x86_64 aarch64 arm mips mipsel; do
  test -x "/usr/local/bin/afl-qemu-trace-${cpu_target}"
done
rm -rf /tmp/aflpp /tmp/aflpp.tar.gz /tmp/qemuafl.tar.gz \
  /tmp/keycodemapdb.tar.gz /tmp/softfloat.tar.gz /tmp/testfloat.tar.gz
