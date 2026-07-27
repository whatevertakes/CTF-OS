#!/usr/bin/env bash
set -Eeuo pipefail

RESTLER_COMMIT=6d984deedbc54aad957fa3da0c7e9e5df23a2aee
RESTLER_SHA256=e5667e4db7bee9fe651cd799fc645c818e0e792a0bdd9ce7520246e0668fa928

apt-get update
apt-get install -y --no-install-recommends ca-certificates curl python3
rm -rf /var/lib/apt/lists/*
curl --fail --location --retry 3 --silent --show-error \
  "https://codeload.github.com/microsoft/restler-fuzzer/tar.gz/${RESTLER_COMMIT}" \
  --output /tmp/restler.tar.gz
printf '%s  %s\n' "$RESTLER_SHA256" /tmp/restler.tar.gz \
  | sha256sum --check --strict -
mkdir -p /tmp/restler /opt/restler
tar -xzf /tmp/restler.tar.gz -C /tmp/restler --strip-components=1
python3 /tmp/restler/build-restler.py --dest_dir /opt/restler
test -f /opt/restler/restler/Restler.dll
dotnet --info >/dev/null
