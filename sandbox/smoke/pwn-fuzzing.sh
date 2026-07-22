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
afl_help="$(afl-fuzz -h 2>&1 || true)"
grep -F "afl-fuzz++${AFLPP_VERSION:-5.02c}" <<<"$afl_help" >/dev/null
echo CTF_OS_AFL_SMOKE_OK
