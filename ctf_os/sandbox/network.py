from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import ipaddress
import json
import re
import socket
from typing import Any
from urllib.parse import urlsplit


class NetworkPolicyError(ValueError):
    pass


PROTOCOLS = frozenset({"tcp", "udp", "http", "https", "tls", "websocket", "wss", "dns", "ssh", "grpc", "custom"})
TCP_PROTOCOLS = frozenset({"tcp", "http", "https", "tls", "websocket", "wss", "ssh", "grpc", "custom"})
UDP_PROTOCOLS = frozenset({"udp", "dns"})
_NC = re.compile(r"nc\s+([^\s]+)\s+([0-9]{1,5})", re.I)
_HOST_PORT = re.compile(r"\[([^]]+)]:(\d{1,5})\Z|([^:]+):(\d{1,5})\Z")
_HOST = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\Z")
_FORBIDDEN_NAMES = {
    "localhost", "host.docker.internal", "gateway.docker.internal",
    "metadata.google.internal", "metadata", "instance-data",
}
_METADATA_IPS = frozenset({"169.254.169.254", "fd00:ec2::254", "100.100.100.200"})
_DOCKER_GATEWAYS = frozenset({"172.17.0.1", "172.18.0.1", "192.168.65.1"})
_DEFAULT_PORTS = {
    "http": 80, "https": 443, "tls": 443, "websocket": 80, "wss": 443,
    "dns": 53, "ssh": 22, "grpc": 443,
}


@dataclass(frozen=True, slots=True)
class Target:
    declared: str
    host: str
    port: int
    scheme: str
    organizer_declared: bool = False
    callback: bool = False

    @property
    def protocol(self) -> str:
        return "tcp" if self.scheme == "nc" else self.scheme

    @property
    def transport(self) -> str:
        return "udp" if self.protocol in UDP_PROTOCOLS else "tcp"

    def to_dict(self) -> dict[str, object]:
        return {
            "declared": self.declared, "host": self.host, "port": self.port,
            "scheme": self.scheme, "protocol": self.protocol,
            "transport": self.transport, "organizer_declared": self.organizer_declared,
            "callback": self.callback,
        }


@dataclass(frozen=True, slots=True)
class ResolvedTarget:
    target: Target
    address: str

    def to_dict(self) -> dict[str, object]:
        return self.target.to_dict() | {"ip": self.address}


def parse_remotes(values: Sequence[str | Mapping[str, Any]]) -> tuple[Target, ...]:
    targets: list[Target] = []
    seen: set[tuple[str, int, str]] = set()
    for value in values:
        target = _parse_target(value)
        _validate_target(target)
        key = (target.host.casefold().rstrip("."), target.port, target.protocol)
        if key in seen:
            raise NetworkPolicyError(f"duplicate authorized remote: {target.declared!r}")
        seen.add(key)
        targets.append(target)
    return tuple(targets)


def resolve_targets(targets: Sequence[Target]) -> tuple[ResolvedTarget, ...]:
    result: list[ResolvedTarget] = []
    seen: set[tuple[str, int, str]] = set()
    for target in targets:
        socktype = socket.SOCK_DGRAM if target.transport == "udp" else socket.SOCK_STREAM
        try:
            records = socket.getaddrinfo(target.host, target.port, socket.AF_UNSPEC, socktype)
        except OSError as exc:
            raise NetworkPolicyError(f"cannot resolve authorized target {target.host!r}: {exc}") from exc
        for record in records:
            try:
                address = str(ipaddress.ip_address(record[4][0]))
            except (ValueError, IndexError, TypeError):
                continue
            _validate_address(address, organizer_declared=target.organizer_declared)
            key = (address, target.port, target.transport)
            if key not in seen:
                seen.add(key)
                result.append(ResolvedTarget(target, address))
        if not any(item.target == target for item in result):
            raise NetworkPolicyError(f"authorized target has no permitted address: {target.host!r}")
    return tuple(result)


def target_matches_observation(target: Target, host: str, port: int, protocol: str) -> bool:
    normalized = protocol.casefold()
    protocol_ok = normalized in {target.protocol, target.transport} or (
        target.protocol == "nc" and normalized == "tcp"
    )
    if port != target.port or not protocol_ok:
        return False
    if host.casefold().rstrip(".") == target.host.casefold().rstrip("."):
        return True
    try:
        observed_ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    try:
        records = socket.getaddrinfo(target.host, target.port, socket.AF_UNSPEC, 0)
    except OSError:
        return False
    return any(str(observed_ip) == str(ipaddress.ip_address(row[4][0])) for row in records)


def _parse_target(value: str | Mapping[str, Any]) -> Target:
    if isinstance(value, Mapping):
        raw = value
        declared = json.dumps(dict(raw), sort_keys=True, separators=(",", ":"))
        host = str(raw.get("host") or "").strip()
        protocol = str(raw.get("protocol") or "tcp").strip().casefold()
        port_raw = raw.get("port", _DEFAULT_PORTS.get(protocol))
        if port_raw is None:
            raise NetworkPolicyError("structured target requires a port for this protocol")
        try:
            port = int(port_raw)
        except (TypeError, ValueError) as exc:
            raise NetworkPolicyError("structured target port must be an integer") from exc
        return Target(
            declared, host, port, protocol,
            organizer_declared=raw.get("organizer_declared") is True,
            callback=raw.get("callback") is True,
        )
    if (
        not isinstance(value, str) or value != value.strip() or not value
        or "\n" in value or "\r" in value
    ):
        raise NetworkPolicyError("remote must not be blank or have surrounding whitespace")
    raw_text = value
    if raw_text.startswith("{"):
        try:
            parsed_json = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise NetworkPolicyError("structured target JSON is malformed") from exc
        if not isinstance(parsed_json, Mapping):
            raise NetworkPolicyError("structured target JSON must be an object")
        return _parse_target(parsed_json)
    nc = _NC.fullmatch(raw_text)
    if nc:
        return Target(raw_text, nc.group(1), int(nc.group(2)), "nc")
    parsed = urlsplit(raw_text)
    if parsed.scheme in PROTOCOLS and parsed.hostname and not parsed.username and not parsed.password:
        try:
            port = parsed.port or _DEFAULT_PORTS.get(parsed.scheme)
        except ValueError as exc:
            raise NetworkPolicyError(f"invalid remote port: {raw_text!r}") from exc
        if port is None:
            raise NetworkPolicyError(f"remote protocol requires an explicit port: {raw_text!r}")
        return Target(raw_text, parsed.hostname, port, parsed.scheme)
    match = _HOST_PORT.fullmatch(raw_text)
    if match:
        host = match.group(1) or match.group(3)
        port = int(match.group(2) or match.group(4))
        return Target(raw_text, host, port, "tcp")
    raise NetworkPolicyError(f"unsupported remote declaration: {raw_text!r}")


def _validate_target(target: Target) -> None:
    if target.protocol not in PROTOCOLS and target.scheme != "nc":
        raise NetworkPolicyError(f"unsupported remote protocol: {target.protocol!r}")
    if not 1 <= target.port <= 65535:
        raise NetworkPolicyError(f"remote port outside 1..65535: {target.port}")
    host = target.host.casefold().rstrip(".")
    if host in _FORBIDDEN_NAMES:
        raise NetworkPolicyError(f"forbidden metadata/host-gateway target: {target.host!r}")
    try:
        ipaddress.ip_address(target.host)
    except ValueError:
        if not _HOST.fullmatch(target.host):
            raise NetworkPolicyError(f"unsafe or malformed remote host: {target.host!r}")
        return
    _validate_address(target.host, organizer_declared=target.organizer_declared)


def _validate_address(value: str, *, organizer_declared: bool) -> None:
    address = ipaddress.ip_address(value)
    if str(address) in _METADATA_IPS:
        raise NetworkPolicyError(f"cloud metadata endpoint is always forbidden: {value}")
    if str(address) in _DOCKER_GATEWAYS:
        raise NetworkPolicyError(f"Docker host gateway is always forbidden: {value}")
    if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified or address.is_reserved:
        raise NetworkPolicyError(f"remote address is not permitted unicast: {value}")
    if address.is_private and not organizer_declared:
        raise NetworkPolicyError(f"private/VPN target requires organizer_declared=true: {value}")
