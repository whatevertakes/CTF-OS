#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

apt_install nodejs npm php-cli php-curl php-sqlite3 sqlite3 redis-tools postgresql-client default-mysql-client
pip_install -r /opt/ctf-os/requirements/web.txt
npm install --global corepack@0.33.0
corepack enable

for command in node npm npx corepack php sqlite3 redis-cli psql mysql; do require_command "$command"; done
for module in flask fastapi uvicorn jwt websockets dns requests httpx bs4 lxml cryptography; do require_import "$module"; done
node -e 'if (Number(process.versions.node.split(".")[0]) < 18) process.exit(1)'
