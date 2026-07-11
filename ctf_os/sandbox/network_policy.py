"""Parse and resolve the narrowly documented CTF remote endpoint formats.

The container firewall consumes resolved IP addresses, not hostnames.  This
keeps DNS changes after container startup from widening an attempt's egress.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
import socket
from collections.abc import Callable
from urllib.parse import urlsplit


class RemotePolicyError(ValueError):
    """Raised when a manifest remote cannot become an exact egress rule."""


_NC = re.compile(r"nc\s+([^\s]+)\s+([0-9]{1,5})", re.ASCII)
_HOST_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")


@dataclass(frozen=True, slots=True)
class RemoteEndpoint:
    """A typed, unresolved endpoint as documented in ``contest.md``."""

    host: str
    port: int
    protocol: str

    def __post_init__(self) -> None:
        if self.protocol != "nc":
            raise RemotePolicyError("HTTP(S) remotes are rejected: Host/TLS-SNI identity enforcement is unavailable")
        _validate_host(self.host)
        _reject_forbidden_host(self.host)
        try:
            literal = ipaddress.ip_address(self.host)
        except ValueError:
            pass
        else:
            if _forbidden_address(literal, allow_private=False):
                raise RemotePolicyError(f"remote host is a disallowed address: {self.host!r}")
        if not 1 <= self.port <= 65535:
            raise RemotePolicyError(f"remote port is outside 1..65535: {self.port}")

    @property
    def transport(self) -> str:
        return "tcp"


@dataclass(frozen=True, slots=True)
class AllowedEndpoint:
    """One exact IP/port rule passed to the attempt container."""

    host: str
    address: str
    port: int
    protocol: str
    source_protocol: str
    allow_private: bool = False

    def __post_init__(self) -> None:
        _validate_host(self.host)
        try:
            parsed = ipaddress.ip_address(self.address)
        except ValueError as exc:
            raise RemotePolicyError(f"remote resolution returned a non-IP address: {self.address!r}") from exc
        if _forbidden_address(parsed, allow_private=self.allow_private):
            raise RemotePolicyError(f"remote resolution returned a disallowed address: {self.address!r}")
        if self.protocol != "tcp":
            raise RemotePolicyError("only TCP remotes are supported by the container policy")
        if self.source_protocol != "nc":
            raise RemotePolicyError("HTTP(S) endpoint policy is rejected without Host/TLS-SNI enforcement")
        if not 1 <= self.port <= 65535:
            raise RemotePolicyError(f"remote port is outside 1..65535: {self.port}")

    def to_policy_dict(self) -> dict[str, object]:
        return {
            "host": self.host,
            "ip": self.address,
            "port": self.port,
            "protocol": self.protocol,
            "source_protocol": self.source_protocol,
        }


Resolver = Callable[[str, int, int, int], list[tuple[object, ...]]]


def parse_remote_endpoints(remote: str | None) -> tuple[RemoteEndpoint, ...]:
    """Accept exactly one TCP ``nc HOST PORT`` declaration.

    A manifest field is deliberately not a mini-shell or a free-form endpoint
    list.  Rejecting ambiguous syntax makes the resulting Docker policy easy to
    review and prevents an author from accidentally granting extra egress.
    """

    if remote is None:
        return ()
    if not isinstance(remote, str):
        raise RemotePolicyError("remote must be one exact HTTP(S) URL or 'nc HOST PORT'")
    if not remote.strip():
        return ()
    if remote != remote.strip():
        raise RemotePolicyError("remote must not have leading or trailing whitespace")

    nc = _NC.fullmatch(remote)
    if nc:
        host, port_text = nc.groups()
        return (RemoteEndpoint(host=host, port=int(port_text), protocol="nc"),)

    if any(character.isspace() for character in remote):
        raise RemotePolicyError("remote URL must not contain whitespace")
    parsed = urlsplit(remote)
    if parsed.scheme not in {"http", "https"}:
        raise RemotePolicyError("remote must use http://, https://, or 'nc HOST PORT'")
    # A destination firewall alone cannot bind HTTP Host or TLS SNI to the
    # manifest identity.  This includes literal-IP URLs: clients can still
    # select an arbitrary Host/SNI virtual host at that address.  Until a
    # bypass-resistant egress mediator exists, no HTTP(S) surface is safe.
    raise RemotePolicyError("HTTP(S) remotes are rejected: Host/TLS-SNI identity enforcement is unavailable")

def resolve_remote_endpoints(
    endpoints: tuple[RemoteEndpoint, ...],
    *,
    resolver: Resolver = socket.getaddrinfo,
    allow_private: bool = False,
) -> tuple[AllowedEndpoint, ...]:
    """Resolve each declared host before Docker starts and freeze exact IPs."""

    if allow_private:
        raise RemotePolicyError("private egress opt-in is disabled; Docker gateway and host-service paths are unsafe")

    allowed: list[AllowedEndpoint] = []
    seen: set[tuple[str, int, str]] = set()
    for endpoint in endpoints:
        try:
            records = resolver(endpoint.host, endpoint.port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        except OSError as exc:
            raise RemotePolicyError(f"could not resolve documented remote {endpoint.host!r}: {exc}") from exc
        addresses: set[str] = set()
        for record in records:
            if len(record) < 5 or record[0] not in {socket.AF_INET, socket.AF_INET6}:
                continue
            sockaddr = record[4]
            if not isinstance(sockaddr, tuple) or not sockaddr:
                continue
            try:
                addresses.add(str(ipaddress.ip_address(str(sockaddr[0]))))
            except ValueError:
                continue
        if not addresses:
            raise RemotePolicyError(f"documented remote {endpoint.host!r} did not resolve to an IP address")
        for address in sorted(addresses, key=lambda item: (ipaddress.ip_address(item).version, item)):
            allowed_endpoint = AllowedEndpoint(
                host=endpoint.host,
                address=address,
                port=endpoint.port,
                protocol=endpoint.transport,
                source_protocol=endpoint.protocol,
                allow_private=allow_private,
            )
            key = (allowed_endpoint.address, allowed_endpoint.port, allowed_endpoint.protocol)
            if key not in seen:
                seen.add(key)
                allowed.append(allowed_endpoint)
    return tuple(allowed)


def _validate_host(value: str) -> None:
    if not isinstance(value, str) or not value or len(value) > 253 or any(character.isspace() for character in value):
        raise RemotePolicyError("remote host must be a non-empty hostname or IP literal")
    try:
        ipaddress.ip_address(value)
        return
    except ValueError:
        pass
    if value.endswith(".") or ":" in value or not all(_HOST_LABEL.fullmatch(label) for label in value.split(".")):
        raise RemotePolicyError(f"remote host is malformed or ambiguous: {value!r}")


_FORBIDDEN_HOSTS = frozenset({
    "localhost", "localhost.localdomain", "host.docker.internal", "gateway.docker.internal",
    "host-gateway", "metadata.google.internal", "instance-data", "metadata",
})
_FORBIDDEN_METADATA_IPS = frozenset({
    "169.254.169.254", "100.100.100.200", "fd00:ec2::254",
})


def _reject_forbidden_host(host: str) -> None:
    if host.casefold().rstrip(".") in _FORBIDDEN_HOSTS:
        raise RemotePolicyError("remote host is a forbidden host gateway or metadata endpoint")


def _forbidden_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address, *, allow_private: bool) -> bool:
    """Allow only public unicast by default; private is an explicit opt-in.

    ``is_global`` handles documentation, carrier-grade NAT, and future
    special-purpose allocations more reliably than a hand-maintained allow
    list.  Even when reviewed private egress is enabled, metadata, gateway
    aliases, loopback, link-local, multicast, unspecified, and reserved space
    remain non-negotiably forbidden.
    """
    if str(address) in _FORBIDDEN_METADATA_IPS:
        return True
    if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified or address.is_reserved:
        return True
    # ``allow_private`` is intentionally ignored.  It remains an argument so
    # callers from older local configs fail closed rather than silently gaining
    # a host/Docker-gateway bypass.
    if address.is_private:
        return True
    return not address.is_global
