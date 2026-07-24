#!/usr/bin/env bash
set -Eeuo pipefail

smoke_root="$(mktemp -d /work/jazzer-smoke.XXXXXX)"
cleanup() { rm -rf -- "$smoke_root"; }
trap cleanup EXIT

cat >"$smoke_root/FuzzTarget.java" <<'EOF'
public class FuzzTarget {
    public static void fuzzerTestOneInput(byte[] data) {
        if (data.length >= 3 && data[0] == 'C' && data[1] == 'T' && data[2] == 'F') {
            System.out.print("");
        }
    }
}
EOF

javac -cp /opt/jazzer/jazzer_standalone.jar "$smoke_root/FuzzTarget.java"
(
  cd "$smoke_root"
  jazzer --cp=. --target_class=FuzzTarget -runs=1 -print_final_stats=1 \
    >jazzer.out 2>&1
)
grep -F 'Instrumented FuzzTarget' "$smoke_root/jazzer.out"
grep -F 'stat::number_of_executed_units:' "$smoke_root/jazzer.out"
echo CTF_OS_JAZZER_SMOKE_OK
