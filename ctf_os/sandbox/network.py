from __future__ import annotations

import ipaddress
import json
import re
import socket
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit


class NetworkPolicyError(ValueError):
    pass


PROTOCOLS = frozenset({"tcp", "udp", "http", "https", "tls", "websocket", "wss", "dns", "ssh", "grpc", "custom"})
TCP_PROTOCOLS = frozenset({"tcp", "http", "https", "tls", "websocket", "wss", "ssh", "grpc", "custom"})
UDP_PROTOCOLS = frozenset({"udp", "dns"})
_NC = re.compile(r"nc\s+([^\s]+)\s+([0-9]{1,5})", re.IGNORECASE)
_HOST_PORT = re.compile(r"\[([^]]+)]:(\d{1,5})\Z|([^:]+):(\d{1,5})\Z")
_HOST = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\Z")
_FORBIDDEN_NAMES = {
    "localhost", "host.docker.internal", "gateway.docker.internal",
    "metadata.google.internal", "metadata", "instance-data",
}
_METADATA_IPS = frozenset({"169.254.169.254", "fd00:ec2::254", "100.100.100.200"})
# Docker/Docker-Desktop default bridge gateways. These are always-blocked as a
# fail-closed floor for offline validation (fingerprinting, parsing) where no
# live daemon inspection has run yet. The authoritative, complete gateway set is
# collected at live sandbox preparation by collect_docker_gateways() below, which
# discovers the real per-network gateways (including custom address pools and
# IPv6) that this static list cannot know about. Policy: an address that is an
# actual runtime Docker gateway is rejected even when organizer_declared=true.
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


def collect_docker_gateways(
    *,
    docker: str = "docker",
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> frozenset[str]:
    """Read-only inspect every Docker network and return all gateway addresses.

    The result always contains the static default floor and additionally every
    real IPv4/IPv6 gateway the daemon currently exposes. Raises NetworkPolicyError
    on any inspection failure so live sandbox preparation fails closed rather than
    granting egress against an unknown gateway set.
    """

    def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
        try:
            return runner(argv, capture_output=True, text=True, timeout=30, check=False)
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as exc:
            raise NetworkPolicyError(f"cannot inspect Docker networks: {exc}") from exc

    listed = _run([docker, "network", "ls", "--format", "{{.ID}}"])
    if listed.returncode:
        raise NetworkPolicyError(
            f"cannot list Docker networks: {(listed.stderr or listed.stdout).strip()}"
        )
    ids = [line.strip() for line in listed.stdout.splitlines() if line.strip()]
    gateways: set[str] = set(_DOCKER_GATEWAYS)
    if not ids:
        return frozenset(gateways)
    inspected = _run([docker, "network", "inspect", *ids])
    if inspected.returncode:
        raise NetworkPolicyError(
            f"Docker network inspect failed: {(inspected.stderr or inspected.stdout).strip()}"
        )
    try:
        rows = json.loads(inspected.stdout)
    except json.JSONDecodeError as exc:
        raise NetworkPolicyError("Docker network inspect returned malformed JSON") from exc
    if not isinstance(rows, list):
        raise NetworkPolicyError("Docker network inspect returned an unexpected shape")
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        ipam = row.get("IPAM")
        configs = ipam.get("Config") if isinstance(ipam, Mapping) else None
        for config in configs or []:
            if not isinstance(config, Mapping):
                continue
            gateway = config.get("Gateway")
            if not gateway:
                continue
            try:
                gateways.add(str(ipaddress.ip_address(str(gateway).strip())))
            except ValueError:
                continue
    return frozenset(gateways)


def parse_remotes(
    values: Sequence[str | Mapping[str, Any]],
    *,
    blocked_gateways: frozenset[str] = _DOCKER_GATEWAYS,
) -> tuple[Target, ...]:
    targets: list[Target] = []
    seen: set[tuple[str, int, str]] = set()
    for value in values:
        target = _parse_target(value)
        _validate_target(target, blocked_gateways)
        key = (target.host.casefold().rstrip("."), target.port, target.protocol)
        if key in seen:
            raise NetworkPolicyError(f"duplicate authorized remote: {target.declared!r}")
        seen.add(key)
        targets.append(target)
    return tuple(targets)


def rebuild_targets(
    rows: Sequence[Mapping[str, Any]],
    *,
    blocked_gateways: frozenset[str] = _DOCKER_GATEWAYS,
) -> tuple[Target, ...]:
    """Reconstruct declared Targets from immutable stored records (RACE/INPUT).

    Used by bootstrap so a child receives the challenge's targets exactly as they
    were declared at preparation time, never a value re-read from a mutable
    manifest after the race started.
    """

    targets: list[Target] = []
    for row in rows:
        if not isinstance(row, Mapping):
            raise NetworkPolicyError("declared target record is malformed")
        try:
            port = int(row["port"])
        except (KeyError, TypeError, ValueError) as exc:
            raise NetworkPolicyError("declared target record has no valid port") from exc
        target = Target(
            declared=str(row.get("declared", "")),
            host=str(row.get("host", "")),
            port=port,
            scheme=str(row.get("scheme", "tcp")),
            organizer_declared=bool(row.get("organizer_declared")),
            callback=bool(row.get("callback")),
        )
        _validate_target(target, blocked_gateways)
        targets.append(target)
    return tuple(targets)


def resolve_targets(
    targets: Sequence[Target],
    *,
    blocked_gateways: frozenset[str] = _DOCKER_GATEWAYS,
) -> tuple[ResolvedTarget, ...]:
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
            _validate_address(
                address,
                organizer_declared=target.organizer_declared,
                blocked_gateways=blocked_gateways,
            )
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


def _validate_target(target: Target, blocked_gateways: frozenset[str]) -> None:
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
    _validate_address(
        target.host,
        organizer_declared=target.organizer_declared,
        blocked_gateways=blocked_gateways,
    )


def _validate_address(
    value: str, *, organizer_declared: bool, blocked_gateways: frozenset[str] = _DOCKER_GATEWAYS
) -> None:
    address = ipaddress.ip_address(value)
    effective = getattr(address, "ipv4_mapped", None) or address
    canonical = str(effective)
    canonical_gateways = {
        str(getattr(candidate, "ipv4_mapped", None) or candidate)
        for raw in blocked_gateways
        for candidate in [ipaddress.ip_address(raw)]
    }
    if canonical in _METADATA_IPS:
        raise NetworkPolicyError(f"cloud metadata endpoint is always forbidden: {value}")
    # A real Docker gateway is forbidden even for organizer-declared private
    # targets: reaching it means reaching a service on the host.
    if canonical in canonical_gateways:
        raise NetworkPolicyError(f"Docker host gateway is always forbidden: {value}")
    if (
        effective.is_loopback
        or effective.is_link_local
        or effective.is_multicast
        or effective.is_unspecified
        or effective.is_reserved
    ):
        raise NetworkPolicyError(f"remote address is not permitted unicast: {value}")
    # RFC 6598 shared CGNAT space (100.64.0.0/10) is neither `is_private` nor
    # globally reachable according to ipaddress. Treat every non-global unicast
    # address like private/VPN space so an implicit declaration cannot reach a
    # carrier, overlay, or host-adjacent network.
    if not effective.is_global and not organizer_declared:
        raise NetworkPolicyError(
            f"private/VPN/non-global target requires organizer_declared=true: {value}"
        )
