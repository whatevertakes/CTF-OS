from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
import socket
from urllib.parse import urlsplit


class NetworkPolicyError(ValueError):
    pass


_NC = re.compile(r"nc\s+([^\s]+)\s+([0-9]{1,5})", re.I)
_HOST = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\Z")
_FORBIDDEN_NAMES = {"localhost", "host.docker.internal", "gateway.docker.internal", "metadata.google.internal", "metadata"}


@dataclass(frozen=True, slots=True)
class Target:
    declared: str
    host: str
    port: int
    scheme: str

    def to_dict(self) -> dict[str, object]:
        return {"declared": self.declared, "host": self.host, "port": self.port, "scheme": self.scheme}


@dataclass(frozen=True, slots=True)
class ResolvedTarget:
    target: Target
    address: str

    def to_dict(self) -> dict[str, object]:
        return self.target.to_dict() | {"ip": self.address, "protocol": "tcp"}


def parse_remotes(values: tuple[str, ...]) -> tuple[Target, ...]:
    targets: list[Target] = []
    seen: set[tuple[str, int]] = set()
    for raw in values:
        if raw != raw.strip() or not raw:
            raise NetworkPolicyError("remote must not be blank or have surrounding whitespace")
        nc = _NC.fullmatch(raw)
        if nc:
            target = Target(raw, nc.group(1), int(nc.group(2)), "nc")
        else:
            parsed = urlsplit(raw)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
                raise NetworkPolicyError(f"remote must be an HTTP(S) URL or exact 'nc HOST PORT': {raw!r}")
            try:
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
            except ValueError as exc:
                raise NetworkPolicyError(f"invalid remote port: {raw!r}") from exc
            target = Target(raw, parsed.hostname, port, parsed.scheme)
        _validate_target(target)
        key = (target.host.casefold(), target.port)
        if key in seen:
            raise NetworkPolicyError(f"duplicate authorized remote: {raw!r}")
        seen.add(key)
        targets.append(target)
    return tuple(targets)


def resolve_targets(targets: tuple[Target, ...]) -> tuple[ResolvedTarget, ...]:
    result: list[ResolvedTarget] = []
    seen: set[tuple[str, int]] = set()
    for target in targets:
        try:
            records = socket.getaddrinfo(target.host, target.port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except OSError as exc:
            raise NetworkPolicyError(f"cannot resolve authorized target {target.host!r}: {exc}") from exc
        for record in records:
            try:
                address = str(ipaddress.ip_address(record[4][0]))
            except (ValueError, IndexError, TypeError):
                continue
            _reject_address(address)
            key = (address, target.port)
            if key not in seen:
                seen.add(key)
                result.append(ResolvedTarget(target, address))
        if not any(item.target == target for item in result):
            raise NetworkPolicyError(f"authorized target has no permitted public address: {target.host!r}")
    return tuple(result)


def _validate_target(target: Target) -> None:
    if not 1 <= target.port <= 65535:
        raise NetworkPolicyError(f"remote port outside 1..65535: {target.port}")
    host = target.host.casefold().rstrip(".")
    if host in _FORBIDDEN_NAMES or not _HOST.fullmatch(target.host):
        try:
            ipaddress.ip_address(target.host)
        except ValueError as exc:
            raise NetworkPolicyError(f"unsafe or malformed remote host: {target.host!r}") from exc
    try:
        ipaddress.ip_address(target.host)
    except ValueError:
        return
    _reject_address(target.host)


def _reject_address(value: str) -> None:
    address = ipaddress.ip_address(value)
    if not address.is_global or address.is_private or address.is_loopback or address.is_link_local or address.is_multicast or address.is_reserved:
        raise NetworkPolicyError(f"remote address is not public unicast: {value}")
