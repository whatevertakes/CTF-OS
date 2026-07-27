#!/usr/bin/env bash
set -Eeuo pipefail

JERRYSCRIPT_COMMIT=38e05b456987a26dc782a72c4221e396c9e35a20
JERRYSCRIPT_SHA256=d013f022f8200ba9ef528d2934f1dc33ef030b715f4db2ca965f3d3696c7ca1d

curl --fail --location --retry 3 --silent --show-error \
  "https://codeload.github.com/jerryscript-project/jerryscript/tar.gz/${JERRYSCRIPT_COMMIT}" \
  --output /tmp/jerryscript.tar.gz
printf '%s  %s\n' "$JERRYSCRIPT_SHA256" /tmp/jerryscript.tar.gz \
  | sha256sum --check --strict -
mkdir -p /tmp/jerryscript
tar -xzf /tmp/jerryscript.tar.gz -C /tmp/jerryscript --strip-components=1
patch -d /tmp/jerryscript -p1 \
  < /tmp/fuzzilli/Targets/Jerryscript/Patches/jerryscript.patch
(
  cd /tmp/jerryscript
  CC=clang python3 tools/build.py \
    --compile-flag=-fsanitize-coverage=trace-pc-guard \
    --profile=es.next --lto=off \
    --compile-flag=-D_POSIX_C_SOURCE=200809 \
    --compile-flag=-Wno-strict-prototypes \
    --compile-flag=-Wno-enum-enum-conversion \
    --compile-flag=-Wno-unterminated-string-initialization \
    --stack-limit=15
)
install -m 0755 /tmp/jerryscript/build/bin/jerry \
  /opt/fuzzilli/bin/jerry-fuzzilli
