#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

FFUF_VERSION=2.2.1
FFUF_SHA256=86307885810d3c36ba4a3e9ba5178c2d9027bba0dd7f4ea39e39e7c972b62396
NUCLEI_VERSION=3.11.0
NUCLEI_SHA256=dc238d6040813e14fc30514dac5a2eb1b430c694f3ca99eee2a5097e55076283
NUCLEI_TEMPLATES_VERSION=10.4.6
NUCLEI_TEMPLATES_COMMIT=7d66fa06cc0a5ad85f7bf35f18cf8ee9218fa9a5
NUCLEI_TEMPLATES_SHA256=bb519f9fe89bfc37ae4bf5590c82507536aa1fc7fa00268d15589a0314643aa7
DALFOX_VERSION=3.1.2
DALFOX_SHA256=ef48d30c183cead88eb89da10bdc1a7fa58a484d175319096075b470f3652fd4
SSTIMAP_COMMIT=d4f09055b15967b0e2265f20eb348a7ec2f25a2c
SSTIMAP_SHA256=6afd688be9faa6888279e1587c1f63bb580e52f086d1ebe994edde5e3c0b691d
KATANA_VERSION=1.6.1
KATANA_SHA256=503754f1bd370c3ef287df6998e317baed2dd75bdd13ea64034f09b80ca393f3
HTTPX_PD_VERSION=1.10.0
HTTPX_PD_SHA256=63eac4dcd6e5c9867c94765fdaaf66e7b4eeae3474a1f06e600e266a1c81a53e
FEROXBUSTER_VERSION=2.13.1
FEROXBUSTER_SHA256=7985c00e6803b0f25d5e9139f7472279f3f4d891429627a5cedc629e53992d80
GRPCURL_VERSION=1.9.3
GRPCURL_SHA256=a926b62a85787ccf73ef8736b3ae554f1242e39d92bb8767a79d6dd23b11d1d5
JWT_TOOL_COMMIT=3bc7407cf2222d6a821dcc19c776e5a1b1cb9a9b
JWT_TOOL_SHA256=9ba64c43d965b3e5119807354abbb50cd40212a8a41c5fef873875e87d72d76d
COMMIX_COMMIT=0d4f2f07725bf95978e94495b12fd6cb5874a3e8
COMMIX_SHA256=2b1b97d5bcbbea4c256b67b9c87862330a681dc259d53ef1830f9844a519a754
PHPGGC_COMMIT=f8aebde3a1abb88b02042fd12a71b4c61d6cfe2c
PHPGGC_SHA256=566d9f270585de42effc5e407070c0c815fefc30bb8842595e7367b37cc1eeba
YSOSERIAL_VERSION=0.0.6
YSOSERIAL_SHA256=2c9bddd6a1a4ec66c1078ea97dacb61eb66d1c41aec7b6d21e3c72214ce170f1
SECLISTS_COMMIT=ffb381d7be6609812f6014de46251537cf8e9ff8

apt_install \
  nodejs npm php-cli php-curl php-sqlite3 sqlite3 redis-tools \
  postgresql-client default-mysql-client chromium chromium-driver
pip_install_locked /opt/ctf-os/requirements-lock/web.txt
python3 -m venv /opt/semgrep-venv
venv_install_locked \
  /opt/semgrep-venv /opt/ctf-os/requirements-lock/isolated/semgrep.txt
ln -s /opt/semgrep-venv/bin/semgrep /usr/local/bin/semgrep
python3 -m venv /opt/mitmproxy-venv
venv_install_locked \
  /opt/mitmproxy-venv /opt/ctf-os/requirements-lock/isolated/mitmproxy.txt
for command in mitmproxy mitmdump mitmweb; do
  ln -s "/opt/mitmproxy-venv/bin/$command" "/usr/local/bin/$command"
done
python3 -m venv /opt/jwt-tool-venv
venv_install_locked \
  /opt/jwt-tool-venv /opt/ctf-os/requirements-lock/isolated/jwt-tool.txt
npm install --global corepack@0.33.0
corepack enable

download_sha256 \
  "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz" \
  /tmp/ffuf.tar.gz "$FFUF_SHA256"
tar -xzf /tmp/ffuf.tar.gz -C /tmp ffuf
install -m 0755 /tmp/ffuf /usr/local/bin/ffuf

download_sha256 \
  "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_amd64.zip" \
  /tmp/katana.zip "$KATANA_SHA256"
unzip -q /tmp/katana.zip katana -d /tmp/katana
install -m 0755 /tmp/katana/katana /usr/local/bin/katana
download_sha256 \
  "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_PD_VERSION}/httpx_${HTTPX_PD_VERSION}_linux_amd64.zip" \
  /tmp/httpx-pd.zip "$HTTPX_PD_SHA256"
unzip -q /tmp/httpx-pd.zip httpx -d /tmp/httpx-pd
install -m 0755 /tmp/httpx-pd/httpx /usr/local/bin/httpx-pd
download_sha256 \
  "https://github.com/epi052/feroxbuster/releases/download/v${FEROXBUSTER_VERSION}/x86_64-linux-feroxbuster.tar.gz" \
  /tmp/feroxbuster.tar.gz "$FEROXBUSTER_SHA256"
tar -xzf /tmp/feroxbuster.tar.gz -C /tmp
install -m 0755 /tmp/feroxbuster /usr/local/bin/feroxbuster
download_sha256 \
  "https://github.com/fullstorydev/grpcurl/releases/download/v${GRPCURL_VERSION}/grpcurl_${GRPCURL_VERSION}_linux_x86_64.tar.gz" \
  /tmp/grpcurl.tar.gz "$GRPCURL_SHA256"
tar -xzf /tmp/grpcurl.tar.gz -C /tmp grpcurl
install -m 0755 /tmp/grpcurl /usr/local/bin/grpcurl

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
rm -rf /tmp/ffuf /tmp/ffuf.tar.gz /tmp/nuclei /tmp/nuclei.zip /tmp/nuclei-templates.tar.gz /tmp/dalfox-extract /tmp/dalfox.tar.gz

download_sha256 "https://github.com/vladko312/SSTImap/archive/${SSTIMAP_COMMIT}.tar.gz" /tmp/sstimap.tar.gz "$SSTIMAP_SHA256"
mkdir -p /opt/sstimap
tar -xzf /tmp/sstimap.tar.gz -C /opt/sstimap --strip-components=1

download_sha256 \
  "https://codeload.github.com/ticarpi/jwt_tool/tar.gz/${JWT_TOOL_COMMIT}" \
  /tmp/jwt-tool.tar.gz "$JWT_TOOL_SHA256"
mkdir -p /opt/jwt-tool
tar -xzf /tmp/jwt-tool.tar.gz -C /opt/jwt-tool --strip-components=1
download_sha256 \
  "https://codeload.github.com/commixproject/commix/tar.gz/${COMMIX_COMMIT}" \
  /tmp/commix.tar.gz "$COMMIX_SHA256"
mkdir -p /opt/commix
tar -xzf /tmp/commix.tar.gz -C /opt/commix --strip-components=1
download_sha256 \
  "https://codeload.github.com/ambionics/phpggc/tar.gz/${PHPGGC_COMMIT}" \
  /tmp/phpggc.tar.gz "$PHPGGC_SHA256"
mkdir -p /opt/phpggc
tar -xzf /tmp/phpggc.tar.gz -C /opt/phpggc --strip-components=1
ln -s /opt/phpggc/phpggc /usr/local/bin/phpggc
download_sha256 \
  "https://github.com/frohoff/ysoserial/releases/download/v${YSOSERIAL_VERSION}/ysoserial-all.jar" \
  /tmp/ysoserial-all.jar "$YSOSERIAL_SHA256"
mkdir -p /opt/ysoserial
install -m 0644 /tmp/ysoserial-all.jar /opt/ysoserial/ysoserial-all.jar

mkdir -p \
  /opt/wordlists/SecLists/Discovery/Web-Content \
  /opt/wordlists/SecLists/Fuzzing/Databases/SQLi \
  /opt/wordlists/SecLists/Fuzzing/XSS/robot-friendly \
  /opt/wordlists/SecLists/Fuzzing
download_sha256 \
  "https://raw.githubusercontent.com/danielmiessler/SecLists/${SECLISTS_COMMIT}/Discovery/Web-Content/raft-small-words.txt" \
  /opt/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt \
  1aadf7dafde5ca68f5e5160c9206f7be6f6fc701775cdea30ba01bbb6d8db8ad
download_sha256 \
  "https://raw.githubusercontent.com/danielmiessler/SecLists/${SECLISTS_COMMIT}/Discovery/Web-Content/raft-small-directories.txt" \
  /opt/wordlists/SecLists/Discovery/Web-Content/raft-small-directories.txt \
  06e1ac7b390c17eb9e0da416d0599c785a1541813daa95b01c676bc92d55185f
download_sha256 \
  "https://raw.githubusercontent.com/danielmiessler/SecLists/${SECLISTS_COMMIT}/Fuzzing/special-chars.txt" \
  /opt/wordlists/SecLists/Fuzzing/special-chars.txt \
  35d0cac8294508c83d31bcdbd263464c78064ea719be4e5a54ce96f4f24d327c
download_sha256 \
  "https://raw.githubusercontent.com/danielmiessler/SecLists/${SECLISTS_COMMIT}/Fuzzing/Databases/SQLi/Generic-SQLi.txt" \
  /opt/wordlists/SecLists/Fuzzing/Databases/SQLi/Generic-SQLi.txt \
  09e5930609e4ce0663505168432796881f493ec0e63643300166d36ed57d40ec
download_sha256 \
  "https://raw.githubusercontent.com/danielmiessler/SecLists/${SECLISTS_COMMIT}/Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt" \
  /opt/wordlists/SecLists/Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt \
  1b7ec661af015daa7d8d67d3c9032099275e346b503ec8686f8b7df4dca3ca69

rm -rf \
  /tmp/sstimap.tar.gz /tmp/katana /tmp/katana.zip /tmp/httpx-pd /tmp/httpx-pd.zip \
  /tmp/feroxbuster /tmp/feroxbuster.tar.gz /tmp/grpcurl /tmp/grpcurl.tar.gz \
  /tmp/jwt-tool.tar.gz /tmp/commix.tar.gz /tmp/phpggc.tar.gz /tmp/ysoserial-all.jar
