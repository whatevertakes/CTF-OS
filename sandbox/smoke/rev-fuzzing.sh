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
fuzzilli_help="$(fuzzilli --help 2>&1 || true)"
grep -F -- '--profile' <<<"$fuzzilli_help"
fuzzil_help="$(fuzzil-tool --help 2>&1 || true)"
grep -Fq 'Usage' <<<"$fuzzil_help"
fuzzilli --profile=jerryscript --jobs=1 --maxIterations=10 \
  --storagePath="$smoke_root/fuzzilli-campaign" --overwrite \
  /usr/local/bin/jerry-fuzzilli >"$smoke_root/fuzzilli.out" 2>&1
test -d "$smoke_root/fuzzilli-campaign/corpus"
echo CTF_OS_JAZZER_SMOKE_OK
echo CTF_OS_FUZZILLI_SMOKE_OK
