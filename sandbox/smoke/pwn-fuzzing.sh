#!/usr/bin/env bash
set -Eeuo pipefail

smoke_root="$(mktemp -d /tmp/afl-smoke.XXXXXX)"
cleanup() { rm -rf -- "$smoke_root"; }
trap cleanup EXIT
cat >"$smoke_root/target.c" <<'EOF'
#include <limits.h>
#include <stdio.h>
#include <string.h>
int main(void) {
    char input[16] = {0};
    size_t length = fread(input, 1, sizeof(input), stdin);
    if (length && input[0] == 'A') puts("branch-a");
    if (length && input[0] == 'B') puts("branch-b");
    if (length >= 5 && !memcmp(input, "CRASH", 5)) {
        volatile int value = INT_MAX;
        value += 1;
        return value;
    }
    return 0;
}
EOF

afl-clang-fast -O0 "$smoke_root/target.c" -o "$smoke_root/instrumented"
printf A | afl-showmap -q -o "$smoke_root/map-a" -- "$smoke_root/instrumented"
printf B | afl-showmap -q -o "$smoke_root/map-b" -- "$smoke_root/instrumented"
test -s "$smoke_root/map-a" && test -s "$smoke_root/map-b"
! cmp -s "$smoke_root/map-a" "$smoke_root/map-b"

AFL_USE_ASAN=1 afl-clang-fast -O0 "$smoke_root/target.c" -o "$smoke_root/asan-build"
AFL_USE_UBSAN=1 afl-clang-fast -O0 "$smoke_root/target.c" -o "$smoke_root/sanitized"
set +e
printf CRASH | UBSAN_OPTIONS=halt_on_error=1 \
  "$smoke_root/sanitized" >"$smoke_root/sanitizer.out" 2>&1
sanitizer_status="$?"
set -e
(( sanitizer_status != 0 ))
grep -Eq 'runtime error|UndefinedBehaviorSanitizer' "$smoke_root/sanitizer.out"

cc -O0 -no-pie "$smoke_root/target.c" -o "$smoke_root/plain"
printf A | afl-showmap -Q -q -o "$smoke_root/map-qemu" -- "$smoke_root/plain"
test -s "$smoke_root/map-qemu"
printf A | afl-showmap -O -q -o "$smoke_root/map-frida" -- "$smoke_root/plain"
test -s "$smoke_root/map-frida"
for cpu_target in x86_64 aarch64 arm mips mipsel; do
  "/usr/local/bin/afl-qemu-trace-${cpu_target}" -h \
    >"$smoke_root/qemu-${cpu_target}.out" 2>&1 || true
  grep -F 'usage:' "$smoke_root/qemu-${cpu_target}.out"
done
afl_help="$(afl-fuzz -h 2>&1 || true)"
grep -F "afl-fuzz++${AFLPP_VERSION:-5.02c}" <<<"$afl_help" >/dev/null

AFL_PATH=/opt/aflnet aflnet-clang-fast -O0 "$smoke_root/target.c" \
  -o "$smoke_root/aflnet-target"
printf A | AFL_PATH=/opt/aflnet /opt/aflnet/afl-showmap -q \
  -o "$smoke_root/map-aflnet" -- "$smoke_root/aflnet-target"
test -s "$smoke_root/map-aflnet"
AFL_PATH=/opt/stateafl stateafl-clang-fast -O0 "$smoke_root/target.c" \
  -o "$smoke_root/stateafl-target"
printf A | AFL_PATH=/opt/stateafl /opt/stateafl/afl-showmap -q \
  -o "$smoke_root/map-stateafl" -- "$smoke_root/stateafl-target"
test -s "$smoke_root/map-stateafl"

cat >"$smoke_root/memcheck.c" <<'EOF'
#include <stdlib.h>
int main(void) {
    char *value = malloc(8);
    if (!value) return 1;
    value[0] = 'V';
    free(value);
    return 0;
}
EOF
cc -O0 -g "$smoke_root/memcheck.c" -o "$smoke_root/memcheck"
valgrind --tool=memcheck --leak-check=full --error-exitcode=99 \
  "$smoke_root/memcheck" >"$smoke_root/valgrind.out" 2>&1
grep -F 'ERROR SUMMARY: 0 errors' "$smoke_root/valgrind.out"

python3 - <<'PY'
from boofuzz import Request, Static

request = Request(
    "ctf-os-boofuzz-smoke",
    children=(Static(name="magic", default_value=b"PING"),),
)
assert request.render() == b"PING"
print("boofuzz=RENDER_OK")
PY
boo --help >/dev/null

cat >"$smoke_root/atheris-smoke.py" <<'PY'
import sys
import atheris

@atheris.instrument_func
def TestOneInput(data):
    if data == b"CTF":
        pass

atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
PY
(
  cd "$smoke_root"
  python3 atheris-smoke.py -runs=1 -print_final_stats=1 \
    >atheris.out 2>&1
)
grep -F 'stat::number_of_executed_units:' "$smoke_root/atheris.out"

mkdir -p "$smoke_root/rust/src"
cat >"$smoke_root/rust/Cargo.toml" <<'EOF'
[package]
name = "ctf-os-cargo-fuzz-smoke"
version = "0.0.0"
edition = "2021"
EOF
cat >"$smoke_root/rust/src/lib.rs" <<'EOF'
pub fn parse(data: &[u8]) -> bool {
    data.starts_with(b"CTF")
}
EOF
(
  cd "$smoke_root/rust"
  cargo fuzz init --fuzzing-workspace=true
  sed -i \
    's/libfuzzer-sys = "0.4"/libfuzzer-sys = "=0.4.13"/' \
    fuzz/Cargo.toml
  grep -F 'libfuzzer-sys = "=0.4.13"' fuzz/Cargo.toml
  CARGO_HOME="$smoke_root/cargo-home" \
    cargo fuzz run fuzz_target_1 -- -runs=1 -print_final_stats=1 \
    >"$smoke_root/cargo-fuzz.out" 2>&1
)
grep -F 'stat::number_of_executed_units:' "$smoke_root/cargo-fuzz.out"

mkdir -p "$smoke_root/honggfuzz-in" "$smoke_root/honggfuzz-out"
printf A >"$smoke_root/honggfuzz-in/seed"
hfuzz-clang -O0 "$smoke_root/target.c" -o "$smoke_root/honggfuzz-target"
honggfuzz --quiet --threads 1 --iterations 1 \
  --input "$smoke_root/honggfuzz-in" --output "$smoke_root/honggfuzz-out" \
  --stdin_input -- "$smoke_root/honggfuzz-target"

printf CTF >"$smoke_root/radamsa-seed"
radamsa -n 2 -o "$smoke_root/radamsa-%n" "$smoke_root/radamsa-seed"
test -s "$smoke_root/radamsa-1"
test -s "$smoke_root/radamsa-2"

printf 'getpid()\n' >"$smoke_root/syz-prog"
syz-prog2c -os linux -arch amd64 -prog "$smoke_root/syz-prog" \
  >"$smoke_root/syz-repro.c"
grep -F 'int main' "$smoke_root/syz-repro.c"
syz_execprog_help="$(syz-execprog -h 2>&1 || true)"
grep -F 'usage: execprog' <<<"$syz_execprog_help" >/dev/null

mkdir -p "$smoke_root/libafl-in"
printf A >"$smoke_root/libafl-in/seed"
(
  cd "$smoke_root"
  set +e
  AFL_CORES=1 AFL_NUM_CORES=1 timeout 8 libafl-fuzz \
    -i "$smoke_root/libafl-in" -o "$smoke_root/libafl-out" \
    -- "$smoke_root/instrumented" \
    >"$smoke_root/libafl.out" 2>&1
  libafl_status="$?"
  set -e
  (( libafl_status == 0 || libafl_status == 124 ))
)
grep -F 'executions:' "$smoke_root/libafl.out"
test -e "$smoke_root/libafl-out/fuzzer_main/fuzzer_stats"
test -s "$smoke_root/libafl-out/fuzzer_main/plot_data"
test -d "$smoke_root/libafl-out/fuzzer_main/queue"
echo CTF_OS_AFL_SMOKE_OK
echo CTF_OS_PWN_LANGUAGE_FUZZING_SMOKE_OK
echo CTF_OS_ADVANCED_FUZZING_SMOKE_OK
