#!/usr/bin/env bash
set -Eeuo pipefail
source /opt/ctf-os/install/lib.sh

for command in \
  node npm npx corepack php sqlite3 redis-cli psql mysql chromium chromedriver \
  ffuf nuclei ctf-nuclei-scan sqlmap dalfox semgrep sstimap schemathesis \
  httpx-pd katana feroxbuster mitmproxy mitmdump grpcurl arjun jwt-tool \
  commix phpggc ysoserial; do
  require_command "$command"
done
for module in flask fastapi uvicorn jwt websockets dns requests httpx bs4 lxml cryptography playwright schemathesis; do
  require_import "$module"
done
/opt/semgrep-venv/bin/python -c 'import semgrep'
node -e 'if (Number(process.versions.node.split(".")[0]) < 18) process.exit(1)'
ffuf -V | grep -Fx 'ffuf version: 2.2.1'
nuclei -version
sqlmap --version
dalfox --version
semgrep --version | grep -Fx '1.171.0'
httpx-pd -version
katana -version
feroxbuster --version
mitmdump --version
grpcurl -version
python3 -c "from importlib.metadata import version; assert version('arjun') == '2.2.7'"
arjun --help >/dev/null
jwt-tool --help >/dev/null
commix --help >/dev/null
phpggc --help >/dev/null
ysoserial_output="$(ysoserial 2>&1 || true)"
grep -F 'Y SO SERIAL?' <<<"$ysoserial_output"
sstimap --help >/dev/null
schemathesis --version | grep -F '4.24.2'
test -s /opt/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt
test -s /opt/wordlists/SecLists/Fuzzing/Databases/SQLi/Generic-SQLi.txt
web_smoke_home="$(mktemp -d /tmp/ctf-os-web-home.XXXXXX)"
chown ctf:ctf "$web_smoke_home"
runuser -u ctf -- env HOME="$web_smoke_home" XDG_CACHE_HOME="$web_smoke_home/cache" \
  /usr/local/bin/ctf-os-web-runtime-smoke
rm -rf -- "$web_smoke_home"
