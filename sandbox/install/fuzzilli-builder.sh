#!/usr/bin/env bash
set -Eeuo pipefail

FUZZILLI_COMMIT=357cc311e8513cb4ef68ea4f3efef5fd1c418abc
FUZZILLI_SHA256=8dea928d3e319f92277fab4107465123a6f535fdfa2dbdbe9cc25dc97b1f6431

apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates cmake curl make ninja-build patch python3
rm -rf /var/lib/apt/lists/*
curl --fail --location --retry 3 --silent --show-error \
  "https://codeload.github.com/googleprojectzero/fuzzilli/tar.gz/${FUZZILLI_COMMIT}" \
  --output /tmp/fuzzilli.tar.gz
printf '%s  %s\n' "$FUZZILLI_SHA256" /tmp/fuzzilli.tar.gz \
  | sha256sum --check --strict -
mkdir -p /tmp/fuzzilli /opt/fuzzilli/bin
tar -xzf /tmp/fuzzilli.tar.gz -C /tmp/fuzzilli --strip-components=1
(
  cd /tmp/fuzzilli
  swift build --configuration release --product FuzzilliCli
  swift build --configuration release --product FuzzILTool
  install -m 0755 .build/release/FuzzilliCli /opt/fuzzilli/bin/FuzzilliCli
  install -m 0755 .build/release/FuzzILTool /opt/fuzzilli/bin/FuzzILTool
  find .build/release -maxdepth 1 -type d -name '*.resources' \
    -exec cp -a '{}' /opt/fuzzilli/bin/ ';'
)
set +e
/opt/fuzzilli/bin/FuzzilliCli --help >/tmp/fuzzilli-help 2>&1
fuzzilli_status="$?"
set -e
(( fuzzilli_status == 0 || fuzzilli_status == 1 ))
grep -Fq -- '--profile' /tmp/fuzzilli-help
