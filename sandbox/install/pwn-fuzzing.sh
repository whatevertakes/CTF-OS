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

apt_install libglib2.0-dev libpixman-1-dev llvm-dev libclang-rt-dev meson
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
(cd /tmp/aflpp && LLVM_CONFIG=/usr/bin/llvm-config make -j2 all)
(cd /tmp/aflpp/qemu_mode && NO_CHECKOUT=1 CPU_TARGET=x86_64 ./build_qemu_support.sh)
(cd /tmp/aflpp && PREFIX=/usr/local make install)

for command in afl-fuzz afl-showmap afl-clang-fast afl-clang-fast++ afl-qemu-trace; do
  require_command "$command"
done
rm -rf /tmp/aflpp /tmp/aflpp.tar.gz /tmp/qemuafl.tar.gz \
  /tmp/keycodemapdb.tar.gz /tmp/softfloat.tar.gz /tmp/testfloat.tar.gz
