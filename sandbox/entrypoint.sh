#!/usr/bin/env bash
# This script begins with the capabilities needed only to install a per-attempt
# firewall, switch to ctf, and then clear the capability bounding set. Docker
# grants no capabilities to worker `exec` processes, and setpriv drops this
# entrypoint's remaining caps before it starts sleep.
set -euo pipefail

: "${CTF_OS_ALLOWED_ENDPOINTS_JSON:=[]}"
export HOME=/home/ctf

apply_firewall() {
    local tool="$1" family="$2"
    "$tool" -F OUTPUT
    "$tool" -P OUTPUT DROP
    "$tool" -A OUTPUT -o lo -j ACCEPT
    "$tool" -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # The host resolves every documented remote before Docker starts. The
    # resulting JSON consists only of exact IP/port/TCP tuples.
    while IFS=$'\t' read -r ip port protocol; do
        [ -n "$ip" ] || continue
        [ "$protocol" = "tcp" ] || exit 64
        case "$port" in
            ''|*[!0-9]*|0) exit 64 ;;
        esac
        if [ "$family" = "4" ]; then
            case "$ip" in *:*) continue ;; esac
        elif [ "$family" = "6" ]; then
            case "$ip" in *:*) ;; *) continue ;; esac
        else
            exit 64
        fi
        "$tool" -A OUTPUT -p tcp -d "$ip" --dport "$port" -j ACCEPT
    done < <(printf '%s' "$CTF_OS_ALLOWED_ENDPOINTS_JSON" | jq -r '.[] | [.ip, (.port|tostring), .protocol] | @tsv')
}

if [ "$CTF_OS_ALLOWED_ENDPOINTS_JSON" != "[]" ]; then
    apply_firewall iptables 4
    apply_firewall ip6tables 6
fi

# `--bounding-set=-all` removes NET_ADMIN, SETUID, SETGID and SETPCAP before
# any worker command runs. The Docker exec builder separately forces `--user ctf`.
exec setpriv --reuid=ctf --regid=ctf --init-groups \
    --bounding-set=-all --inh-caps=-all --ambient-caps=-all -- "$@"
