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
    and (.capabilities | length == 35)
    and all(.capabilities[]; .available == true)
    and all(
        .capabilities[]
        | select(
            .name == "web_response_summary_v1"
            or .name == "pwn_crash_v1"
            or .name == "pwn_runtime_snapshot_v1"
            or .name == "pwn_exploit_effect_v1"
            or .name == "pwn_interaction_v1"
            or
            .name == "rev_inventory_v2"
            or .name == "rev_safe_output"
            or .name == "rev_stdin_exec"
            or .name == "rev_runtime_exec_v1"
            or .name == "data_transcript_v1"
            or .name == "forensic_evidence_index_v1"
        );
        .attestation.schema_version == 1
        and (.attestation.contract_id | type == "string")
        and (.attestation.contract_version | type == "number")
        and (
            .attestation.path
            | startswith("/opt/ctf-templates/web/")
              or startswith("/opt/ctf-templates/pwn/")
              or startswith("/opt/ctf-templates/rev/")
              or startswith("/opt/ctf-templates/common/")
              or startswith("/opt/ctf-templates/forensic/")
        )
        and (.attestation.sha256 | test("^[0-9a-f]{64}$"))
    )
' "${test_root}/managed-capabilities.json" >/dev/null

required_tools=(
    aarch64-linux-gnu-gcc avr-gcc avr-gdb avr-objdump bkcrack
    cryptominisat5 crypto-python ctf-browser ctf-egress-proxy
    ctf-network-smoke ctf-web-probe
    ctf-sqlite-readonly evtxexport ewfinfo ewfverify fls frida-trace
    hash_extender mactime mips-linux-gnu-gcc mipsel-linux-gnu-gcc
    msoffcrypto-tool pahole pdfimages playwright pw-python qemu-img
    qemu-aarch64-static qemu-mips-static qemu-mipsel-static
    qemu-riscv64-static qemu-system-aarch64 qemu-system-avr
    qemu-system-riscv64 rabin2 riscv64-linux-gnu-gcc ropr sage-python
    sccainfo simavr uncompyle6 unsquashfs usnjls wasm2wat web-python
    wine wine64
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

ctf-sqlite-readonly --self-test
ctf-tools --json toolbox digital-forensics >"${test_root}/forensic-toolbox.json"
jq -e '
    .command == "toolbox"
    and .category == "forensic"
    and (.categories == ["forensic", "system", "orchestration", "korean"])
    and any(.tools[]; .name == "ctf-sqlite-readonly")
    and any(.tools[]; .name == "sccainfo")
    and any(.tools[]; .name == "ktext")
    and all(.tools[]; .category != "web" and .category != "pwn")
' "${test_root}/forensic-toolbox.json" >/dev/null
ctf-tools --json --search sqlite3 >"${test_root}/sqlite-search.json"
jq -e '
    .count == 2
    and all(.tools[]; .name == "ctf-sqlite-readonly" and .available == true)
' "${test_root}/sqlite-search.json" >/dev/null
ctf-tools --json --info checksec \
    | jq -e '.found == true and .tool.path == "/usr/bin/checksec"' >/dev/null

python3 - "${test_root}/artifact.sqlite" <<'PY'
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
connection.execute("CREATE TABLE events(id INTEGER PRIMARY KEY, value TEXT)")
connection.execute("INSERT INTO events(value) VALUES('ready')")
connection.commit()
connection.close()
PY
sqlite_before=$(sha256sum "${test_root}/artifact.sqlite")
ctf-sqlite-readonly "${test_root}/artifact.sqlite" \
    'SELECT id,value FROM events' >"${test_root}/sqlite-result.json"
jq -e '
    .ok == true and .columns == ["id", "value"]
    and .rows == [[1, "ready"]] and .truncated == false
' "${test_root}/sqlite-result.json" >/dev/null
[[ "$(sha256sum "${test_root}/artifact.sqlite")" == "${sqlite_before}" ]]
set +e
ctf-sqlite-readonly "${test_root}/artifact.sqlite" \
    "ATTACH DATABASE '${test_root}/forbidden.sqlite' AS forbidden" \
    >"${test_root}/sqlite-denied.json"
sqlite_denied_status=$?
set -e
[[ "${sqlite_denied_status}" -eq 1 ]]
jq -e '.ok == false and .error == "query_denied"' \
    "${test_root}/sqlite-denied.json" >/dev/null
[[ ! -e "${test_root}/forbidden.sqlite" ]]

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
stegseek --version 2>&1 | grep -F 'StegSeek ' >/dev/null
zsteg --help | grep -F 'Usage: zsteg ' >/dev/null
ffmpeg -version | grep -F 'ffmpeg version ' >/dev/null
sox --version | grep -F 'SoX v' >/dev/null
zbarimg --version | grep -E '^[0-9]+[.]' >/dev/null
vol --help | grep -F 'usage: vol ' >/dev/null

functional_probes=(
    volatility3 volatility-symbols sleuthkit ewf tshark zeek
    tesseract tesseract-korean hwp
    stegseek zsteg ffmpeg sox zbar
)
for probe in "${functional_probes[@]}"; do
    timeout --signal=TERM --kill-after=2s 20s \
        ctf-capability-smoke "${probe}"
done

[[ "$(sha256sum /opt/ctf-capability-fixtures/charshape.hwp \
    | cut -d' ' -f1)" == \
    "8eb333ab110db6f91d7e426d507d41ca09cacd4d40d945188b5ec40663d7576b" ]]
/opt/venvs/vol3/bin/python - <<'PY'
import importlib.metadata

assert importlib.metadata.version("volatility3") == "2.28.0"
PY
/opt/venvs/hwp/bin/python - <<'PY'
import importlib.metadata

assert importlib.metadata.version("pyhwp") == "0.1b15"
assert importlib.metadata.version("olefile") == "0.47"
assert importlib.metadata.version("chardet") == "7.4.3"
assert importlib.metadata.version("six") == "1.17.0"
PY
gem list --local --exact zsteg --version 0.2.14 \
    | grep -Fx 'zsteg (0.2.14)' >/dev/null

[[ "$(readlink -f /usr/local/lib/ctf-cuda/libnvrtc.so)" == \
    */site-packages/nvidia/cu13/lib/libnvrtc.so.13 ]]
[[ "$(readlink -f /usr/local/lib/ctf-cuda/libnvrtc.so.1)" == \
    */site-packages/nvidia/cu13/lib/libnvrtc.so.13 ]]
[[ "$(readlink -f /usr/local/lib/ctf-cuda/libcudart.so)" == \
    */site-packages/nvidia/cu13/lib/libcudart.so.13 ]]
mapfile -t nvrtc_builtins_links < <(
    find /usr/local/lib/ctf-cuda -maxdepth 1 -type l \
        -name 'libnvrtc-builtins.so.*' -print
)
[[ "${#nvrtc_builtins_links[@]}" -eq 1 ]]
[[ "$(readlink -f "${nvrtc_builtins_links[0]}")" == \
    */site-packages/nvidia/cu13/lib/libnvrtc-builtins.so.* ]]

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

cat >"${test_root}/native-oracle.c" <<'C'
#include <stdio.h>
#include <string.h>

static const char accepted[] = "OPEN-SESAME";

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], accepted) == 0) {
        puts("REV_OK_93D1");
        return 0;
    }
    puts("REV_NO");
    return 7;
}
C
gcc -O0 -fno-pie -no-pie -fno-stack-protector -Wl,-z,noexecstack \
    "${test_root}/native-oracle.c" -o "${test_root}/native-oracle"
"${test_root}/native-oracle" OPEN-SESAME \
    | grep -Fx 'REV_OK_93D1' >/dev/null
set +e
"${test_root}/native-oracle" WRONG >"${test_root}/native-control.txt"
native_control_status=$?
set -e
[[ "${native_control_status}" -eq 7 ]]
grep -Fx 'REV_NO' "${test_root}/native-control.txt" >/dev/null
/usr/bin/checksec --file="${test_root}/native-oracle" \
    >"${test_root}/checksec.txt"
grep -F 'NX enabled' "${test_root}/checksec.txt" >/dev/null
grep -F 'No PIE' "${test_root}/checksec.txt" >/dev/null
ROPgadget --binary "${test_root}/native-oracle" --only 'ret' \
    >"${test_root}/ropgadget.txt"
grep -F 'Unique gadgets found:' "${test_root}/ropgadget.txt" >/dev/null
rabin2 -j -I "${test_root}/native-oracle" >"${test_root}/rabin2.json"
jq -e '
    .info.bintype == "elf" and .info.arch == "x86" and .info.bits == 64
    and .info.nx == true and .info.pic == false
' "${test_root}/rabin2.json" >/dev/null
r2 -q -2 -c 'aaa;afl~main;q' "${test_root}/native-oracle" \
    | grep -F 'main' >/dev/null
strings "${test_root}/native-oracle" | grep -Fx 'OPEN-SESAME' >/dev/null
strings "${test_root}/native-oracle" | grep -Fx 'REV_OK_93D1' >/dev/null
/opt/venvs/main/bin/python - "${test_root}/native-oracle" <<'PY'
import sys
from pwn import ELF

binary = ELF(sys.argv[1], checksec=False)
assert binary.bits == 64
assert binary.pie is False
assert binary.nx is True
assert binary.symbols["main"] > 0
PY

cat >"${test_root}/cross-ready.c" <<'C'
#include <stdio.h>
int main(void) {
    puts("CTFOS_CROSS_READY");
    return 0;
}
C
while read -r compiler emulator label; do
    output="${test_root}/cross-${label}"
    "${compiler}" -static -O2 "${test_root}/cross-ready.c" -o "${output}"
    "${emulator}" "${output}" | grep -Fx 'CTFOS_CROSS_READY' >/dev/null
done <<'CROSS'
aarch64-linux-gnu-gcc qemu-aarch64-static aarch64
mips-linux-gnu-gcc qemu-mips-static mips
mipsel-linux-gnu-gcc qemu-mipsel-static mipsel
riscv64-linux-gnu-gcc qemu-riscv64-static riscv64
CROSS

cat >"${test_root}/avr-ready.c" <<'C'
#include <avr/io.h>

volatile uint8_t ctfos_marker;

int main(void) {
    ctfos_marker = 0x5a;
    __asm__ __volatile__("break");
    for (;;) {}
}
C
avr-gcc -mmcu=atmega328p -Os "${test_root}/avr-ready.c" \
    -o "${test_root}/avr-ready.elf"
avr-objdump -d "${test_root}/avr-ready.elf" >"${test_root}/avr-ready.asm"
grep -F '<main>:' "${test_root}/avr-ready.asm" >/dev/null
grep -F 'break' "${test_root}/avr-ready.asm" >/dev/null
avr-gdb -q -batch "${test_root}/avr-ready.elf" \
    -ex 'info address main' >"${test_root}/avr-gdb.txt"
grep -F 'Symbol "main" is' "${test_root}/avr-gdb.txt" >/dev/null
set +e
timeout --signal=TERM --kill-after=1s 3s \
    simavr -m atmega328p -f 16000000 "${test_root}/avr-ready.elf" \
    >"${test_root}/simavr.txt" 2>&1
simavr_status=$?
set -e
[[ "${simavr_status}" -eq 0 || "${simavr_status}" -eq 124 ]]
! grep -Eiq 'unknown mcu|could not.*(read|load)|invalid.*elf' \
    "${test_root}/simavr.txt"

wine --version | grep -F 'wine-9.0' >/dev/null
wine64 --version | grep -F 'wine-9.0' >/dev/null
mono --version | grep -F 'Mono JIT compiler version' >/dev/null
ropr --version | grep -F 'ropr 0.2.27' >/dev/null
bkcrack --version | grep -F '1.8.1' >/dev/null
qemu-system-aarch64 --version | grep -F 'QEMU emulator version' >/dev/null
qemu-system-arm --version | grep -F 'QEMU emulator version' >/dev/null
qemu-system-avr --version | grep -F 'QEMU emulator version' >/dev/null
qemu-system-mips --version | grep -F 'QEMU emulator version' >/dev/null
qemu-system-riscv64 --version | grep -F 'QEMU emulator version' >/dev/null
qemu-system-x86_64 --version | grep -F 'QEMU emulator version' >/dev/null
qemu-system-avr -machine help | grep -F 'Arduino' >/dev/null
qemu-system-riscv64 -machine help | grep -F 'virt' >/dev/null

cat >"${test_root}/boot-exit.S" <<'ASM'
.code16
.global _start
_start:
    movb $0x10, %al
    outb %al, $0xf4
    hlt
.org 510
.word 0xaa55
ASM
as --32 "${test_root}/boot-exit.S" -o "${test_root}/boot-exit.o"
ld -m elf_i386 --oformat binary -Ttext 0x7c00 \
    "${test_root}/boot-exit.o" -o "${test_root}/boot-exit.bin"
[[ "$(stat -c %s "${test_root}/boot-exit.bin")" -eq 512 ]]
set +e
/opt/ctf-templates/pwn/qemu-headless.sh --timeout 10 \
    qemu-system-x86_64 \
    -machine pc \
    -drive "file=${test_root}/boot-exit.bin,format=raw,if=floppy" \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    >"${test_root}/qemu-boot.txt" 2>&1
qemu_boot_status=$?
set -e
[[ "${qemu_boot_status}" -eq 33 ]]

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
    ctf-web-probe pw-python qemu-system-aarch64 qemu-system-arm \
    qemu-system-avr qemu-system-mips qemu-system-riscv64 qemu-system-x86_64 \
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

ilspy = next(tool for tool in manifest["tools"] if tool["name"] == "ilspycmd")
assert ilspy["path"] == "/opt/dotnet-tools/ilspycmd", ilspy
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

printf '{"manifest_tools":%s,"browser_title":"CTF Browser Ready","interactive_sql_clients":0,"sqlite_readonly":1}\n' \
    "$(jq '.tools | length' /tools/manifest.json)"
