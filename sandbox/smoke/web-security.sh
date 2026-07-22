#!/usr/bin/env bash
set -Eeuo pipefail

smoke_root="$(mktemp -d /work/web-security-smoke.XXXXXX)"
server_pid=""
cleanup() {
  [[ -z "$server_pid" ]] || kill "$server_pid" 2>/dev/null || true
  rm -rf -- "$smoke_root"
  rm -f -- /artifacts/nuclei-smoke.jsonl
}
trap cleanup EXIT
cat >"$smoke_root/server.py" <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query)
        body = "CTF_OS_NUCLEI_FINDING" if parsed.path == "/marker" else query.get("q", ["ok"])[0]
        encoded = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)
    def log_message(self, *args):
        pass

HTTPServer(("127.0.0.1", 18080), Handler).serve_forever()
PY
python3 "$smoke_root/server.py" &
server_pid="$!"
for _ in 1 2 3 4 5; do
  curl -fsS http://127.0.0.1:18080/ >/dev/null && break
  sleep 0.2
done
ctf-nuclei-scan http://127.0.0.1:18080 ctf-local-http.yaml nuclei-smoke.jsonl
grep -q 'ctf-os-local-smoke' /artifacts/nuclei-smoke.jsonl

cat >"$smoke_root/app.py" <<'PY'
def run(value):
    return eval(value)
PY
cat >"$smoke_root/app.js" <<'JS'
function run(value) { return eval(value); }
JS
cat >"$smoke_root/app.php" <<'PHP'
<?php function run($value) { return unserialize($value); }
PHP
cat >"$smoke_root/App.java" <<'JAVA'
class App { Process run(String value) throws Exception { return Runtime.getRuntime().exec(value); } }
JAVA
semgrep --config /opt/ctf-os/rules/semgrep/ctf-web-sinks.yml \
  --metrics off --disable-version-check --json "$smoke_root" >"$smoke_root/semgrep.json"
python3 - "$smoke_root/semgrep.json" <<'PY'
import json, sys
ids = {finding["check_id"] for finding in json.load(open(sys.argv[1]))["results"]}
expected = {"ctf.python.dynamic-code", "ctf.javascript.dynamic-code", "ctf.php.dangerous-call", "ctf.java.process-exec"}
assert all(any(check_id.endswith(rule_id) for check_id in ids) for rule_id in expected), (expected, ids)
PY

sqlmap -hh >/dev/null
sqlmap --batch --url http://127.0.0.1:18080/?id=1 --level 1 --risk 1 \
  --technique B --timeout 2 --retries 0 --flush-session \
  --output-dir "$smoke_root/sqlmap" >/dev/null
dalfox url --url 'http://127.0.0.1:18080/?q=smoke' --param q \
  --skip-mining --skip-discovery --workers 1 --timeout 2 --scan-timeout 5 \
  --format json >/dev/null
echo CTF_OS_WEB_SECURITY_SMOKE_OK
