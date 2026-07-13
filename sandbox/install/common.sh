#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

apt_install \
  bash ca-certificates curl wget git jq ripgrep file binutils xxd hexedit \
  unzip zip p7zip-full tar gzip bzip2 xz-utils zstd netcat-openbsd socat \
  nmap dnsutils iproute2 iputils-ping openssl strace ltrace procps psmisc \
  util-linux findutils gawk gcc g++ make cmake ninja-build pkg-config clang lld \
  python3 python3-dev python3-pip python3-venv ruby ruby-dev default-jre-headless \
  iptables tini locales gnupg libmagic1 libxml2 libxslt1.1

python3 -m pip install --break-system-packages --no-cache-dir -r /opt/ctf-os/requirements/common.txt

for command in python3 curl wget git jq rg file objdump strings readelf nm xxd nmap gcc g++ cmake clang ruby java; do
  require_command "$command"
done
for module in requests httpx bs4 lxml yaml rich numpy scipy PIL networkx sympy z3 Crypto cryptography capstone unicorn; do
  require_import "$module"
done
