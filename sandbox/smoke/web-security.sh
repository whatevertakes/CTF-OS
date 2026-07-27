#!/usr/bin/env bash
set -Eeuo pipefail

smoke_root="$(mktemp -d /work/web-security-smoke.XXXXXX)"
export HOME="$smoke_root/home"
export XDG_CONFIG_HOME="$HOME/.config"
export XDG_CACHE_HOME="$HOME/.cache"
export XDG_DATA_HOME="$HOME/.local/share"
mkdir -p "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" "$XDG_DATA_HOME"
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
cat >"$smoke_root/openapi.json" <<'JSON'
{
  "openapi": "3.0.0",
  "info": {"title": "CTF-OS local smoke", "version": "1.0.0"},
  "servers": [{"url": "http://127.0.0.1:18080"}],
  "paths": {
    "/marker": {
      "get": {
        "operationId": "marker",
        "responses": {
          "200": {
            "description": "local marker",
            "content": {
              "text/html": {"schema": {"type": "string"}}
            }
          }
        }
      }
    }
  }
}
JSON
ctf-nuclei-scan http://127.0.0.1:18080 ctf-local-http.yaml nuclei-smoke.jsonl
grep -q 'ctf-os-local-smoke' /artifacts/nuclei-smoke.jsonl
schemathesis run "$smoke_root/openapi.json" \
  --url http://127.0.0.1:18080 --phases fuzzing --max-examples 3 \
  --workers 1 --generation-deterministic --no-color \
  >"$smoke_root/schemathesis.out" 2>&1
echo CTF_OS_SCHEMATHESIS_SMOKE_OK
printf '%s\n' http://127.0.0.1:18080/marker \
  | httpx-pd -silent >"$smoke_root/httpx-pd.out"
grep -F 'http://127.0.0.1:18080/marker' "$smoke_root/httpx-pd.out"
katana -u http://127.0.0.1:18080/marker -silent -depth 1 \
  >"$smoke_root/katana.out"
grep -F 'http://127.0.0.1:18080/marker' "$smoke_root/katana.out"
(
  cd "$smoke_root"
  restler compile --api_spec "$smoke_root/openapi.json" \
    >"$smoke_root/restler-compile.out" 2>&1
)
test -s "$smoke_root/Compile/grammar.py"
(
  cd "$smoke_root"
  restler fuzz-lean \
    --grammar_file "$smoke_root/Compile/grammar.py" \
    --dictionary_file "$smoke_root/Compile/dict.json" \
    --target_ip 127.0.0.1 --target_port 18080 --no_ssl \
    --no_results_analyzer >"$smoke_root/restler-fuzz-lean.out" 2>&1
)
echo CTF_OS_RESTLER_FUZZ_LEAN_SMOKE_OK

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
