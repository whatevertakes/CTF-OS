#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

FFUF_VERSION=2.1.0
NUCLEI_VERSION=3.11.0
NUCLEI_SHA256=dc238d6040813e14fc30514dac5a2eb1b430c694f3ca99eee2a5097e55076283
NUCLEI_TEMPLATES_VERSION=10.4.6
NUCLEI_TEMPLATES_COMMIT=7d66fa06cc0a5ad85f7bf35f18cf8ee9218fa9a5
NUCLEI_TEMPLATES_SHA256=bb519f9fe89bfc37ae4bf5590c82507536aa1fc7fa00268d15589a0314643aa7
DALFOX_VERSION=3.1.2
DALFOX_SHA256=ef48d30c183cead88eb89da10bdc1a7fa58a484d175319096075b470f3652fd4
SSTIMAP_COMMIT=d4f09055b15967b0e2265f20eb348a7ec2f25a2c
SSTIMAP_SHA256=6afd688be9faa6888279e1587c1f63bb580e52f086d1ebe994edde5e3c0b691d

apt_install \
  nodejs npm php-cli php-curl php-sqlite3 sqlite3 redis-tools \
  postgresql-client default-mysql-client chromium chromium-driver golang-go
pip_install_locked /opt/ctf-os/requirements-lock/web.txt
python3 -m venv /opt/semgrep-venv
venv_install_locked \
  /opt/semgrep-venv /opt/ctf-os/requirements-lock/isolated/semgrep.txt
ln -s /opt/semgrep-venv/bin/semgrep /usr/local/bin/semgrep
npm install --global corepack@0.33.0
corepack enable

go_workspace="$(mktemp -d /tmp/ctf-os-ffuf.XXXXXX)"
GOBIN=/usr/local/bin GOPATH="$go_workspace/path" GOCACHE="$go_workspace/cache" \
  go install "github.com/ffuf/ffuf/v2@v${FFUF_VERSION}"
rm -rf -- "$go_workspace"

download_sha256 \
  "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
  /tmp/nuclei.zip "$NUCLEI_SHA256"
unzip -q /tmp/nuclei.zip nuclei -d /tmp/nuclei
install -m 0755 /tmp/nuclei/nuclei /usr/local/bin/nuclei
download_sha256 \
  "https://codeload.github.com/projectdiscovery/nuclei-templates/tar.gz/${NUCLEI_TEMPLATES_COMMIT}" \
  /tmp/nuclei-templates.tar.gz "$NUCLEI_TEMPLATES_SHA256"
mkdir -p /opt/nuclei-templates
tar -xzf /tmp/nuclei-templates.tar.gz -C /opt/nuclei-templates --strip-components=1

download_sha256 \
  "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VERSION}/dalfox-v${DALFOX_VERSION}-linux-x86_64.tar.gz" \
  /tmp/dalfox.tar.gz "$DALFOX_SHA256"
mkdir -p /tmp/dalfox-extract
tar -xzf /tmp/dalfox.tar.gz -C /tmp/dalfox-extract --strip-components=1
install -m 0755 /tmp/dalfox-extract/dalfox /usr/local/bin/dalfox
rm -rf /tmp/nuclei /tmp/nuclei.zip /tmp/nuclei-templates.tar.gz /tmp/dalfox-extract /tmp/dalfox.tar.gz

download_sha256 "https://github.com/vladko312/SSTImap/archive/${SSTIMAP_COMMIT}.tar.gz" /tmp/sstimap.tar.gz "$SSTIMAP_SHA256"
mkdir -p /opt/sstimap
tar -xzf /tmp/sstimap.tar.gz -C /opt/sstimap --strip-components=1
rm -f /tmp/sstimap.tar.gz
