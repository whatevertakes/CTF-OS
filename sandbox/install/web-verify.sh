#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

for command in node npm npx corepack php sqlite3 redis-cli psql mysql chromium chromedriver ffuf nuclei ctf-nuclei-scan sqlmap dalfox semgrep; do
  require_command "$command"
done
for module in flask fastapi uvicorn jwt websockets dns requests httpx bs4 lxml cryptography playwright; do
  require_import "$module"
done
/opt/semgrep-venv/bin/python -c 'import semgrep'
node -e 'if (Number(process.versions.node.split(".")[0]) < 18) process.exit(1)'
ffuf -V
nuclei -version
sqlmap --version
dalfox --version
semgrep --version
web_smoke_home="$(mktemp -d /tmp/ctf-os-web-home.XXXXXX)"
chown ctf:ctf "$web_smoke_home"
runuser -u ctf -- env HOME="$web_smoke_home" XDG_CACHE_HOME="$web_smoke_home/cache" \
  /usr/local/bin/ctf-os-web-runtime-smoke
rm -rf -- "$web_smoke_home"
