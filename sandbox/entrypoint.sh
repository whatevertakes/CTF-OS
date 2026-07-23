#!/usr/bin/env bash
# This script begins with the capabilities needed only to install a per-attempt
# firewall, switch to ctf, and then clear the capability bounding set. Docker
# grants no capabilities to worker `exec` processes, and setpriv drops this
# entrypoint's remaining caps before it starts sleep.
set -euo pipefail

: "${CTF_OS_ALLOWED_ENDPOINTS_JSON:=[]}"
: "${CTF_OS_LOCAL_ENDPOINTS_JSON:=[]}"
# All mutable tool state stays in the attempt-private tmpfs. This also prevents
# accidental use of host browser/cloud/container credentials and profiles.
export HOME=/work/home
export XDG_CONFIG_HOME=/work/home/.config
export XDG_CACHE_HOME=/work/home/.cache
export XDG_RUNTIME_DIR=/work/runtime
export TMPDIR=/work/tmp
export JAVA_TOOL_OPTIONS="-Duser.home=$HOME"
export AWS_SHARED_CREDENTIALS_FILE=/work/credentials/aws
export AWS_CONFIG_FILE=/work/credentials/aws-config
export AZURE_CONFIG_DIR=/work/credentials/azure
export CLOUDSDK_CONFIG=/work/credentials/gcloud
export KUBECONFIG=/work/credentials/kubeconfig
# Create worker-owned state directly as ctf. This avoids granting CAP_CHOWN;
# the short-lived UID/GID switching capabilities are dropped below.
setpriv --reuid=ctf --regid=ctf --init-groups -- sh -c '
  mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" "$XDG_RUNTIME_DIR" "$TMPDIR" /work/credentials
  chmod 0700 "$HOME" "$XDG_RUNTIME_DIR" "$TMPDIR" /work/credentials
  if command -v ares >/dev/null 2>&1; then
    mkdir -p "$HOME/Ares"
    if [ ! -e "$HOME/Ares/config.toml" ]; then
      install -m 0600 /opt/ctf-os/ares-config.toml "$HOME/Ares/config.toml"
    fi
  fi
'

apply_firewall() {
    local tool="$1" family="$2"
    "$tool" -F OUTPUT
    "$tool" -P OUTPUT DROP
    "$tool" -A OUTPUT -o lo -j ACCEPT
    "$tool" -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # The host resolves every documented remote before Docker starts. The
    # resulting JSON consists only of exact IP/port/transport tuples.
    while IFS=$'\t' read -r ip port protocol; do
        [ -n "$ip" ] || continue
        case "$protocol" in tcp|udp) ;; *) exit 64 ;; esac
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
        "$tool" -A OUTPUT -p "$protocol" -d "$ip" --dport "$port" -j ACCEPT
    done < <(printf '%s' "$CTF_OS_ALLOWED_ENDPOINTS_JSON" | jq -r '.[] | [.ip, (.port|tostring), .transport] | @tsv')
}

apply_local_firewall() {
    local tool="$1" family="$2"
    "$tool" -F OUTPUT
    "$tool" -P OUTPUT DROP
    "$tool" -A OUTPUT -o lo -j ACCEPT
    "$tool" -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    while IFS=$'\t' read -r host port; do
        [ -n "$host" ] || continue
        case "$port" in
            ''|*[!0-9]*|0) exit 64 ;;
        esac
        while read -r ip; do
            [ -n "$ip" ] || continue
            if [ "$family" = "4" ]; then
                case "$ip" in *:*) continue ;; esac
                "$tool" -A OUTPUT -p tcp -d "$ip" --dport "$port" -j ACCEPT
            elif [ "$family" = "6" ]; then
                case "$ip" in *:*) ;; *) continue ;; esac
                "$tool" -A OUTPUT -p tcp -d "$ip" --dport "$port" -j ACCEPT
            else
                exit 64
            fi
        done < <(getent ahosts "$host" | awk '{print $1}' | sort -u)
    done < <(
        printf '%s' "$CTF_OS_LOCAL_ENDPOINTS_JSON" |
            jq -r '.[] | capture("^(?:(?:https?|tcp|tls|wss?|grpc)://)?(?<host>[^:/]+):(?<port>[0-9]+)$") | [.host, .port] | @tsv'
    )
}

if [ "$CTF_OS_ALLOWED_ENDPOINTS_JSON" != "[]" ]; then
    apply_firewall iptables 4
    apply_firewall ip6tables 6
elif [ "$CTF_OS_LOCAL_ENDPOINTS_JSON" != "[]" ]; then
    apply_local_firewall iptables 4
    apply_local_firewall ip6tables 6
fi

# `--bounding-set=-all` removes NET_ADMIN, SETUID, SETGID and SETPCAP before
# any worker command runs. The Docker exec builder separately forces `--user ctf`.
exec setpriv --reuid=ctf --regid=ctf --init-groups \
    --bounding-set=-all --inh-caps=-all --ambient-caps=-all -- "$@"
