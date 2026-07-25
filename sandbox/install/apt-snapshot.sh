#!/usr/bin/env bash
set -Eeuo pipefail

lock="${1:-/opt/ctf-os/apt-snapshot.lock}"
[[ -f "$lock" && ! -L "$lock" ]] || {
  echo "APT snapshot lock is missing or unsafe: $lock" >&2
  exit 1
}

debian="$(sed -n 's/^debian=//p' "$lock")"
debian_security="$(sed -n 's/^debian_security=//p' "$lock")"
for value in "$debian" "$debian_security"; do
  [[ "$value" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || {
    echo "APT snapshot timestamp is invalid: $value" >&2
    exit 1
  }
done

cat >/etc/apt/sources.list.d/debian.sources <<EOF
Types: deb
URIs: http://snapshot.debian.org/archive/debian/${debian}/
Suites: bookworm bookworm-updates
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: http://snapshot.debian.org/archive/debian-security/${debian_security}/
Suites: bookworm-security
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EOF

cat >/etc/apt/apt.conf.d/99ctf-os-snapshot <<'EOF'
Acquire::Check-Valid-Until "false";
Acquire::Retries "5";
EOF
