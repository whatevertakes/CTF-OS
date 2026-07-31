#!/usr/bin/env bash
set -euo pipefail

test_root=$(mktemp -d)
server_pid=""
hanging_server_pid=""

cleanup() {
    if [[ -n "${hanging_server_pid}" ]]; then
        kill "${hanging_server_pid}" >/dev/null 2>&1 || true
        wait "${hanging_server_pid}" 2>/dev/null || true
    fi
    if [[ -n "${server_pid}" ]]; then
        kill "${server_pid}" >/dev/null 2>&1 || true
        wait "${server_pid}" 2>/dev/null || true
    fi
    rm -rf -- "${test_root}"
}
trap cleanup EXIT

[[ -r /tools/manifest.json ]]
[[ ! -e /tools/failed.txt ]]
jq -e '
    .schema_version == 1
    and (.failed == [])
    and all(.tools[]; .available == true and (.path | startswith("/")))
' /tools/manifest.json >/dev/null

ctf-capabilities --json >"${test_root}/managed-capabilities.json"
jq -e '
    .schema_version == 2
    and (.capabilities | length == 32)
    and all(.capabilities[]; .available == true)
    and all(
        .capabilities[]
        | select(
            .name == "pwn_crash_v1"
            or .name == "pwn_runtime_snapshot_v1"
            or .name == "pwn_exploit_effect_v1"
            or .name == "pwn_interaction_v1"
            or
            .name == "rev_inventory_v2"
            or .name == "rev_safe_output"
            or .name == "rev_stdin_exec"
            or .name == "forensic_evidence_index_v1"
        );
        .attestation.schema_version == 1
        and (.attestation.contract_id | type == "string")
        and (.attestation.contract_version | type == "number")
        and (
            .attestation.path
            | startswith("/opt/ctf-templates/pwn/")
              or startswith("/opt/ctf-templates/rev/")
              or startswith("/opt/ctf-templates/forensic/")
        )
        and (.attestation.sha256 | test("^[0-9a-f]{64}$"))
    )
' "${test_root}/managed-capabilities.json" >/dev/null

required_tools=(
    bkcrack cryptominisat5 crypto-python ctf-browser ctf-egress-proxy
    ctf-network-smoke ctf-web-probe
    evtxexport ewfinfo ewfverify fls frida-trace hash_extender
    msoffcrypto-tool pahole pdfimages playwright pw-python qemu-img
    qemu-system-aarch64 rabin2 ropr sage-python uncompyle6 unsquashfs
    wasm2wat web-python wine wine64
)
for tool in "${required_tools[@]}"; do
    jq -e --arg tool "${tool}" \
        'any(.tools[]; .name == $tool and .available == true)' \
        /tools/manifest.json >/dev/null
    command -v -- "${tool}" >/dev/null
done

for removed in sqlmap sqlite3 mysql psql; do
    ! command -v -- "${removed}" >/dev/null 2>&1
done
[[ ! -e /opt/venvs/sqlmap ]]

python - <<'PY'
import importlib.metadata

import bs4
import cysignals
import fpylll
import gf2bv
import h2
import h2spacex
import lxml
import pysat
import scapy
import websockets
from gf2bv import LinearSystem
from pysat.solvers import Solver

assert importlib.metadata.version("h2spacex") == "1.2.2"
assert importlib.metadata.version("python-sat") == "1.9.dev7"
assert scapy.__version__ == "2.7.0"
system = LinearSystem([1, 1])
a, b = system.gens()
solutions = list(system.solve_all([a ^ b ^ 1]))
assert solutions
for solver_name in ("cadical300", "kissat404"):
    with Solver(name=solver_name, bootstrap_with=[[1], [-1, 2]]) as solver:
        assert solver.solve()
    with Solver(name=solver_name, bootstrap_with=[[1], [-1]]) as solver:
        assert not solver.solve()
PY

set +e
printf 'p cnf 2 2\n1 0\n-1 2 0\n' \
    | cryptominisat5 --verb 0 >"${test_root}/cryptominisat.out"
cryptominisat_status=$?
set -e
[[ "${cryptominisat_status}" -eq 10 ]]
grep -Fx 's SATISFIABLE' "${test_root}/cryptominisat.out" >/dev/null

fls -V | grep -F 'The Sleuth Kit ver' >/dev/null
ewfinfo -V | grep -F 'ewfinfo 20140814' >/dev/null
tshark --version | grep -F 'TShark (Wireshark)' >/dev/null
zeek --version | grep -F 'zeek version' >/dev/null
tesseract --version | grep -F 'tesseract 5.' >/dev/null
tesseract --list-langs >"${test_root}/tesseract-langs.txt"
grep -Fx 'kor' "${test_root}/tesseract-langs.txt" >/dev/null
grep -Fx 'kor_vert' "${test_root}/tesseract-langs.txt" >/dev/null
hwp5txt --version | grep -F 'hwp5txt ' >/dev/null
stegseek --version | grep -F 'StegSeek ' >/dev/null
zsteg --help | grep -F 'Usage: zsteg ' >/dev/null
ffmpeg -version | grep -F 'ffmpeg version ' >/dev/null
sox --version | grep -F 'SoX v' >/dev/null
zbarimg --version | grep -E '^[0-9]+[.]' >/dev/null
vol --help | grep -F 'usage: vol ' >/dev/null

for symbol_archive in windows linux mac; do
    archive="/opt/volatility3/symbols/${symbol_archive}.zip"
    [[ -s "${archive}" ]]
    [[ "$(od -An -tx1 -N4 "${archive}" | tr -d ' \n')" == "504b0304" ]]
done

[[ "$(readlink -f /usr/local/lib/ctf-cuda/libnvrtc.so)" == \
    */site-packages/nvidia/cu13/lib/libnvrtc.so.13 ]]
[[ "$(readlink -f /usr/local/lib/ctf-cuda/libnvrtc.so.1)" == \
    */site-packages/nvidia/cu13/lib/libnvrtc.so.13 ]]
[[ "$(readlink -f /usr/local/lib/ctf-cuda/libcudart.so)" == \
    */site-packages/nvidia/cu13/lib/libcudart.so.13 ]]

sage-python - <<'PY'
import cuso
from Crypto.Util.number import long_to_bytes

assert long_to_bytes(0x435446) == b"CTF"
PY

for extension in curl mbstring dom SimpleXML gd; do
    php -m | grep -Fxi "${extension}" >/dev/null
done
for extension in mysqli pdo_mysql sqlite3; do
    ! php -m | grep -Fxi "${extension}" >/dev/null
done

hash_extender \
    --data data --secret 6 --append append \
    --signature 6036708eba0d11f6ef52ad44e8b74d5b --format md5 \
    | grep -F 'New signature: 6ee582a1669ce442f3719c47430dadee' \
    >/dev/null

printf '{"n":3233,"e":17,"c":2790,"d":2753}\n' >"${test_root}/rsa.json"
sage /opt/ctf-templates/crypto/rsa.sage "${test_root}/rsa.json" \
    >"${test_root}/rsa-summary.json"
jq -e '.ok == true and .hex == "41"' "${test_root}/rsa-summary.json" >/dev/null

mkdir -p "${test_root}/site"
printf '<!doctype html><title>CTF Browser Ready</title><p id="ready">ok</p>\n' \
    >"${test_root}/site/index.html"
printf '%s\n' \
    '<!doctype html><title>CTF Tall Page</title>' \
    '<style>html,body{margin:0;width:100%;height:2000px;background:linear-gradient(#f00,#00f)}</style>' \
    >"${test_root}/site/tall.html"
python3 -m http.server 18080 --bind 127.0.0.1 \
    --directory "${test_root}/site" >"${test_root}/http.log" 2>&1 &
server_pid=$!
for _ in {1..100}; do
    if curl -fsS http://127.0.0.1:18080/ >/dev/null 2>&1; then
        break
    fi
    sleep 0.02
done
curl -fsS http://127.0.0.1:18080/ >/dev/null
ctf-browser http://127.0.0.1:18080/ --timeout 15 --screenshot \
    >"${test_root}/browser-summary.json"
jq -e '
    .ok == true
    and .status == 200
    and .title == "CTF Browser Ready"
    and .saved_html_bytes > 0
' "${test_root}/browser-summary.json" >/dev/null
jq -e '
    .ok == true
    and .response.status == 200
    and .response.title == "CTF Browser Ready"
' /work/web/browser.json >/dev/null
[[ -s /work/web/browser.html && -s /work/web/browser.png ]]

ctf-browser http://127.0.0.1:18080/tall.html \
    --timeout 15 --screenshot --full-page \
    --max-full-page-height 3000 --max-screenshot-pixels 4000000 \
    >"${test_root}/browser-full-page-summary.json"
python3 - <<'PY'
import json
import struct
from pathlib import Path

png = Path("/work/web/browser.png").read_bytes()
assert png[:8] == b"\x89PNG\r\n\x1a\n"
width, height = struct.unpack(">II", png[16:24])
assert (width, height) == (1280, 2000), (width, height)
metadata = json.loads(Path("/work/web/browser.json").read_text(encoding="utf-8"))
assert metadata["screenshot"] == {
    "width": 1280,
    "height": 2000,
    "pixels": 2_560_000,
    "saved_bytes": len(png),
}
PY

set +e
ctf-browser http://127.0.0.1:18080/tall.html \
    --timeout 15 --screenshot --full-page --max-full-page-height 1024 \
    >"${test_root}/browser-height-limit-summary.json"
height_limit_status=$?
set -e
[[ "${height_limit_status}" -eq 2 ]]
jq -e '
    .error == "ScreenshotLimitExceeded"
    and .screenshot_height == 2000
    and .max_full_page_height == 1024
' "${test_root}/browser-height-limit-summary.json" >/dev/null
[[ ! -e /work/web/browser.png ]]

set +e
ctf-browser http://127.0.0.1:18080/ \
    --timeout 15 --screenshot --max-screenshot-bytes 1 \
    >"${test_root}/browser-byte-limit-summary.json"
byte_limit_status=$?
set -e
[[ "${byte_limit_status}" -eq 2 ]]
jq -e '
    .error == "ScreenshotLimitExceeded"
    and .screenshot_bytes > 1
    and .max_screenshot_bytes == 1
' "${test_root}/browser-byte-limit-summary.json" >/dev/null
[[ ! -e /work/web/browser.png ]]

python3 - <<'PY' &
import socket

server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", 18081))
server.listen()
while True:
    connection, _ = server.accept()
    while connection.recv(65536):
        pass
PY
hanging_server_pid=$!
for _ in {1..100}; do
    if bash -c 'exec 3<>/dev/tcp/127.0.0.1/18081' 2>/dev/null; then
        break
    fi
    sleep 0.02
done
set +e
timeout --signal=TERM --kill-after=1s 5s \
    ctf-browser http://127.0.0.1:18081/ --timeout 1 \
    >"${test_root}/browser-deadline-summary.json"
deadline_status=$?
set -e
[[ "${deadline_status}" -eq 2 ]]
jq -e '.error == "BrowserDeadlineExceeded"' \
    "${test_root}/browser-deadline-summary.json" >/dev/null
python3 - <<'PY'
from pathlib import Path

remaining = []
for entry in Path("/proc").iterdir():
    if not entry.name.isdigit():
        continue
    try:
        command = (entry / "cmdline").read_bytes()
    except OSError:
        continue
    if b"playwright/driver/node" in command or b"chrome-headless-shell" in command:
        remaining.append((entry.name, command.replace(b"\0", b" ")[:500]))
assert not remaining, remaining
PY

qemu-img create -q -f qcow2 "${test_root}/disk.qcow2" 1M
qemu-img info --output=json "${test_root}/disk.qcow2" \
    | jq -e '.format == "qcow2"' >/dev/null
mksquashfs "${test_root}/site" "${test_root}/firmware.sqfs" \
    -noappend -quiet -processors 1
unsquashfs -s "${test_root}/firmware.sqfs" >/dev/null

printf '(module (func (export "answer") (result i32) i32.const 42))\n' \
    >"${test_root}/answer.wat"
wat2wasm "${test_root}/answer.wat" -o "${test_root}/answer.wasm"
wasm2wat "${test_root}/answer.wasm" | grep -F 'i32.const 42' >/dev/null
wasm-opt "${test_root}/answer.wasm" -O -o "${test_root}/answer-opt.wasm"
[[ -s "${test_root}/answer-opt.wasm" ]]

wine --version | grep -F 'wine-9.0' >/dev/null
wine64 --version | grep -F 'wine-9.0' >/dev/null
mono --version | grep -F 'Mono JIT compiler version' >/dev/null
ropr --version | grep -F 'ropr 0.2.27' >/dev/null
bkcrack --version | grep -F '1.8.1' >/dev/null
qemu-system-aarch64 --version | grep -F 'QEMU emulator version' >/dev/null
qemu-system-mips --version | grep -F 'QEMU emulator version' >/dev/null
qemu-system-x86_64 --version | grep -F 'QEMU emulator version' >/dev/null

assert_noarg_exit_2() {
    local tool=$1
    local status
    set +e
    timeout --signal=TERM --kill-after=1s 5s "${tool}" \
        </dev/null >/dev/null 2>&1
    status=$?
    set -e
    [[ "${status}" -eq 2 ]]
}

for tool in \
    crypto-python ctf-browser ctf-egress-proxy ctf-network-smoke \
    ctf-web-probe pw-python qemu-system-mips qemu-system-x86_64 \
    sage-python web-python wine wine64
do
    assert_noarg_exit_2 "${tool}"
done

python3 - <<'PY'
import json
import os
import pathlib
import subprocess
import tempfile

with open("/tools/manifest.json", encoding="utf-8") as manifest_file:
    manifest = json.load(manifest_file)

invocations = sorted(
    {(tool["name"], tool["path"]) for tool in manifest["tools"]}
)
timeouts = []
crashes = []
missing = []
with tempfile.TemporaryDirectory(prefix="ctf-noarg-") as work:
    for name, path in invocations:
        executable = pathlib.Path(path)
        if not executable.is_file() or not os.access(executable, os.X_OK):
            missing.append(f"{name}:{path}")
            continue
        result = subprocess.run(
            [
                "timeout",
                "--signal=TERM",
                "--kill-after=1s",
                "5s",
                path,
            ],
            cwd=work,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if result.returncode in (124, 137):
            timeouts.append(f"{name}:{result.returncode}")
        elif result.returncode in (134, 139, -6, -11):
            crashes.append(f"{name}:{result.returncode}")

assert not missing, missing
assert not timeouts, timeouts
assert not crashes, crashes
PY

printf '{"manifest_tools":%s,"browser_title":"CTF Browser Ready","sql_tools":0}\n' \
    "$(jq '.tools | length' /tools/manifest.json)"
