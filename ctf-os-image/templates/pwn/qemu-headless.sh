#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
Usage: qemu-headless.sh [--timeout SECONDS] QEMU_SYSTEM QEMU_ARGS...

Run one bounded TCG guest with no display, monitor, daemon, or network backend.
QEMU_SYSTEM must be a packaged qemu-system-* basename. Use the challenge
sandbox's explicit KVM flow instead of adding -enable-kvm here.
EOF
  exit 2
}

deadline=60
if [[ ${1:-} == --timeout ]]; then
  [[ $# -ge 3 ]] || usage
  deadline=$2
  shift 2
fi
[[ $# -ge 2 ]] || usage
[[ "$deadline" =~ ^[1-9][0-9]{0,3}$ ]] || usage
((deadline <= 3600)) || usage

tool=$1
shift
case "$tool" in
  qemu-system-aarch64|qemu-system-arm|qemu-system-avr|qemu-system-mips|qemu-system-riscv64|qemu-system-x86_64)
    ;;
  *)
    printf 'error: unsupported QEMU system executable: %s\n' "$tool" >&2
    exit 2
    ;;
esac
executable=$(command -v -- "$tool" 2>/dev/null || true)
[[ -n "$executable" && -x "$executable" ]] || {
  printf 'error: QEMU system executable is unavailable: %s\n' "$tool" >&2
  exit 127
}

for argument in "$@"; do
  lowered=${argument,,}
  normalized=${lowered//[[:space:]]/}
  case "$normalized" in
    -accel|-accel=*|-add-fd|-add-fd=*|-audio|-audio=*|-audiodev|-audiodev=*|\
    -blockdev|-blockdev=*|-chardev|-chardev=*|-daemonize|-debugcon|\
    -debugcon=*|-display|-display=*|-enable-kvm|-gdb|-gdb=*|-incoming|\
    -incoming=*|-iscsi|-iscsi=*|-mon|-mon=*|-monitor|-monitor=*|-net|-net=*|\
    -netdev|-netdev=*|-nographic|-nic|-nic=*|-parallel|-parallel=*|-pidfile|\
    -plugin|-plugin=*|-qmp|-qmp=*|-qmp-pretty|-qmp-pretty=*|-readconfig|\
    -readconfig=*|-s|-serial|-serial=*|-set|-set=*|-spice|-spice=*|-vnc|\
    -vnc=*|-websocket|-websocket=*|-writeconfig|-writeconfig=*|*accel=*|\
    *\"driver\":\"curl\"*|*\"driver\":\"ftp\"*|*\"driver\":\"ftps\"*|\
    *\"driver\":\"gluster\"*|*\"driver\":\"http\"*|*\"driver\":\"https\"*|\
    *\"driver\":\"iscsi\"*|*\"driver\":\"nbd\"*|*\"driver\":\"rbd\"*|\
    *\"driver\":\"ssh\"*|*\"type\":\"inet\"*|\
    *driver=curl*|*driver=ftp*|*driver=ftps*|*driver=gluster*|*driver=http*|\
    *driver=https*|*driver=iscsi*|*driver=nbd*|*driver=rbd*|*driver=ssh*|\
    *ftp://*|*ftps://*|*gluster://*|*http://*|*https://*|*iscsi://*|*nbd:*|\
    *nbd+unix://*|*rbd:*|*server.type=inet*|*ssh://*|*tftp://*)
      printf 'error: unsafe or conflicting QEMU option: %s\n' "$argument" >&2
      exit 2
      ;;
  esac
done

exec timeout --foreground --signal=TERM --kill-after=2s "${deadline}s" \
  "$executable" \
  -display none \
  -monitor none \
  -serial stdio \
  -no-reboot \
  -net none \
  -accel tcg \
  "$@"
