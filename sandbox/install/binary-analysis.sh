#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

TEMURIN_VERSION=21.0.11_10
TEMURIN_SHA256=4b2220e232a97997b436ca6ab15cbf70171ecff52958a46159dfa5a8c44ca4de
GHIDRA_VERSION=12.1.2
GHIDRA_RELEASE_DATE=20260605
GHIDRA_SHA256=b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d
CAPA_VERSION=9.4.0
CAPA_SHA256=07800a1d20a21eb18fc98716e2ae81b668e0c9a04defd588c8aa17ea3d3281e4
CAPA_RULES_COMMIT=aed45e2571ebf7d2330e3daddbb5c472cc54966e
CAPA_RULES_SHA256=2a7eb0c558e2f4436003c9d8a35587e520b2d96c6ea2793d27189a195e74a66b

apt_install libglib2.0-0 libstdc++6
pip_install -r /opt/ctf-os/requirements/binary-analysis.txt

download_sha256 \
  "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.11%2B10/OpenJDK21U-jdk_x64_linux_hotspot_${TEMURIN_VERSION}.tar.gz" \
  /tmp/temurin.tar.gz "$TEMURIN_SHA256"
mkdir -p /opt/java
tar -xzf /tmp/temurin.tar.gz -C /opt/java --strip-components=1

download_sha256 \
  "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_RELEASE_DATE}.zip" \
  /tmp/ghidra.zip "$GHIDRA_SHA256"
unzip -q /tmp/ghidra.zip -d /opt
mv "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC" /opt/ghidra
ln -s /opt/ghidra/support/analyzeHeadless /usr/local/bin/analyzeHeadless
pip_install --no-index \
  --find-links=/opt/ghidra/Ghidra/Features/PyGhidra/pypkg/dist \
  pyghidra==3.1.0 jpype1==1.5.2 packaging==25.0

download_sha256 \
  "https://github.com/mandiant/capa/releases/download/v${CAPA_VERSION}/capa-v${CAPA_VERSION}-linux.zip" \
  /tmp/capa.zip "$CAPA_SHA256"
unzip -q /tmp/capa.zip -d /tmp/capa
mkdir -p /opt/capa
install -m 0755 /tmp/capa/capa /opt/capa/capa

download_sha256 \
  "https://codeload.github.com/mandiant/capa-rules/tar.gz/${CAPA_RULES_COMMIT}" \
  /tmp/capa-rules.tar.gz "$CAPA_RULES_SHA256"
mkdir -p /opt/capa-rules
tar -xzf /tmp/capa-rules.tar.gz -C /opt/capa-rules --strip-components=1

for command in java javac analyzeHeadless ctf-ghidra-headless frida frida-ps capa; do
  require_command "$command"
done
for module in frida pyghidra; do require_import "$module"; done
java -version 2>&1 | grep -q 'version "21\.'
capa --version | grep -F "$CAPA_VERSION"
frida --version | grep -F 17.16.4
/usr/local/bin/ctf-os-binary-analysis-smoke
rm -rf /tmp/temurin.tar.gz /tmp/ghidra.zip /tmp/capa /tmp/capa.zip /tmp/capa-rules.tar.gz
