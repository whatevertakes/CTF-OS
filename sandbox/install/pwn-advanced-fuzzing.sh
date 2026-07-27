#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

GO_VERSION=1.26.5
GO_SHA256=5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053
SYZKALLER_COMMIT=492bab153dea5e0e414bd0bbf60c3871267255ed
SYZKALLER_SHA256=a03e68fdd99a5047a3b4c6c374fd03394bd4f4ee994690c22bad593b7c1be553
HONGGFUZZ_COMMIT=cf8b66a4d09f4d4d786d96e3c46d9141fb4e98e2
HONGGFUZZ_SHA256=82030a3c5dad01c2de602929333e1f2337957e074e973eaa6b42530a6309da2b
RADAMSA_COMMIT=5c32c29e9f7d5f0c7fef10fa9a969f78e4bde95f
RADAMSA_SHA256=41f9fa5866cfc3488c018b289553a7d9b0bb69473a598fbf478aa61587f8278c
RADAMSA_OL_SHA256=fca85dae36910108598d8a4a244df7a8c2719e7803ac46d270762ece4aefc55c
RADAMSA_HEX_COMMIT=e95ebd38e4f7ef8e3d4e653f432e43ce0a804ca6
RADAMSA_HEX_SHA256=ee349b23a3426f46037174e78dd0dd3eb7f334da7f196f3a0d3279f9cba5879d
apt_install \
  libunwind-dev libbfd-dev binutils-dev liblzma-dev libblocksruntime-dev \
  clang-format-19
ln -s /usr/bin/clang-format-19 /usr/local/bin/clang-format

download_sha256 \
  "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
  /tmp/go.tar.gz "$GO_SHA256"
mkdir -p /opt/go
tar -xzf /tmp/go.tar.gz -C /opt/go --strip-components=1
ln -s /opt/go/bin/go /usr/local/bin/go
ln -s /opt/go/bin/gofmt /usr/local/bin/gofmt

download_sha256 \
  "https://codeload.github.com/google/syzkaller/tar.gz/${SYZKALLER_COMMIT}" \
  /tmp/syzkaller.tar.gz "$SYZKALLER_SHA256"
mkdir -p /opt/syzkaller
tar -xzf /tmp/syzkaller.tar.gz -C /opt/syzkaller --strip-components=1
(
  cd /opt/syzkaller
  PATH="/opt/go/bin:$PATH" make -j2 HOSTOS=linux HOSTARCH=amd64 \
    TARGETOS=linux TARGETARCH=amd64 TARGETVMARCH=amd64
)
for syz_tool in /opt/syzkaller/bin/syz-*; do
  test -f "$syz_tool" || continue
  ln -s "$syz_tool" "/usr/local/bin/$(basename "$syz_tool")"
done
ln -s /opt/syzkaller/bin/linux_amd64/syz-executor \
  /usr/local/bin/syz-executor
ln -s /opt/syzkaller/bin/linux_amd64/syz-execprog \
  /usr/local/bin/syz-execprog

download_sha256 \
  "https://codeload.github.com/google/honggfuzz/tar.gz/${HONGGFUZZ_COMMIT}" \
  /tmp/honggfuzz.tar.gz "$HONGGFUZZ_SHA256"
mkdir -p /tmp/honggfuzz
tar -xzf /tmp/honggfuzz.tar.gz -C /tmp/honggfuzz --strip-components=1
(cd /tmp/honggfuzz && make -j2 && make install)

download_sha256 \
  "https://gitlab.com/akihe/radamsa/-/archive/${RADAMSA_COMMIT}/radamsa-${RADAMSA_COMMIT}.tar.gz" \
  /tmp/radamsa.tar.gz "$RADAMSA_SHA256"
mkdir -p /tmp/radamsa
tar -xzf /tmp/radamsa.tar.gz -C /tmp/radamsa --strip-components=1
download_sha256 \
  https://haltp.org/files/ol-0.2.2.c.gz \
  /tmp/radamsa/ol.c.gz "$RADAMSA_OL_SHA256"
download_sha256 \
  "https://gitlab.com/owl-lisp/hex/-/archive/${RADAMSA_HEX_COMMIT}/hex-${RADAMSA_HEX_COMMIT}.tar.gz" \
  /tmp/radamsa-hex.tar.gz "$RADAMSA_HEX_SHA256"
mkdir -p /tmp/radamsa/lib/hex
tar -xzf /tmp/radamsa-hex.tar.gz -C /tmp/radamsa/lib/hex --strip-components=1
(cd /tmp/radamsa && make -j2 && make PREFIX=/usr/local install)

for command in \
  go gofmt syz-manager syz-prog2c syz-repro syz-execprog syz-executor \
  honggfuzz hfuzz-clang hfuzz-clang++ radamsa clang-format; do
  require_command "$command"
done
go version | grep -F "go${GO_VERSION}"
syz-prog2c -h >/dev/null 2>&1
syz_execprog_help="$(syz-execprog -h 2>&1 || true)"
grep -F 'usage: execprog' <<<"$syz_execprog_help" >/dev/null
honggfuzz --help >/dev/null
radamsa_output="$(printf CTF | radamsa -n 1)"
test -n "$radamsa_output"
rm -rf \
  /tmp/go.tar.gz /tmp/syzkaller.tar.gz /tmp/honggfuzz /tmp/honggfuzz.tar.gz \
  /tmp/radamsa /tmp/radamsa.tar.gz /tmp/radamsa-hex.tar.gz
