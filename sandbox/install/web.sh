#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

FFUF_VERSION=2.1.0

apt_install \
  nodejs npm php-cli php-curl php-sqlite3 sqlite3 redis-tools \
  postgresql-client default-mysql-client chromium chromium-driver golang-go
pip_install -r /opt/ctf-os/requirements/web.txt
npm install --global corepack@0.33.0
corepack enable

go_workspace="$(mktemp -d /tmp/ctf-os-ffuf.XXXXXX)"
GOBIN=/usr/local/bin GOPATH="$go_workspace/path" GOCACHE="$go_workspace/cache" \
  go install "github.com/ffuf/ffuf/v2@v${FFUF_VERSION}"
rm -rf -- "$go_workspace"

for command in node npm npx corepack php sqlite3 redis-cli psql mysql chromium chromedriver ffuf; do require_command "$command"; done
for module in flask fastapi uvicorn jwt websockets dns requests httpx bs4 lxml cryptography playwright; do require_import "$module"; done
node -e 'if (Number(process.versions.node.split(".")[0]) < 18) process.exit(1)'
ffuf -V
web_smoke_home="$(mktemp -d /tmp/ctf-os-web-home.XXXXXX)"
chown ctf:ctf "$web_smoke_home"
runuser -u ctf -- env HOME="$web_smoke_home" XDG_CACHE_HOME="$web_smoke_home/cache" \
  /usr/local/bin/ctf-os-web-runtime-smoke
rm -rf -- "$web_smoke_home"
