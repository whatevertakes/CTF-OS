"""H3/RH3 (runtime Docker gateway collection) and RH4 (multi-IP attribution)."""

from __future__ import annotations

import subprocess

import pytest

from ctf_os.sandbox import runtime as runtime_module
from ctf_os.sandbox.network import (
    NetworkPolicyError,
    collect_docker_gateways,
    parse_remotes,
)
from ctf_os.sandbox.runtime import _target_identity, firewall_packets


def _fake_network_runner(inspect_json: str, *, ls_code: int = 0, inspect_code: int = 0):
    def runner(argv, **kwargs):
        if argv[:3] == ["docker", "network", "ls"]:
            return subprocess.CompletedProcess(argv, ls_code, "netid1\nnetid2\n", "")
        if argv[:3] == ["docker", "network", "inspect"]:
            return subprocess.CompletedProcess(argv, inspect_code, inspect_json, "")
        raise AssertionError(f"unexpected argv: {argv}")

    return runner


def test_collect_docker_gateways_includes_dynamic_and_ipv6() -> None:
    inspect = """[
      {"IPAM": {"Config": [{"Subnet": "172.20.0.0/16", "Gateway": "172.20.0.1"}]}},
      {"IPAM": {"Config": [{"Subnet": "fd00:dead::/64", "Gateway": "fd00:dead::1"}]}}
    ]"""
    gateways = collect_docker_gateways(runner=_fake_network_runner(inspect))
    assert "172.20.0.1" in gateways
    assert "fd00:dead::1" in gateways
    # Static floor is always retained.
    assert "172.17.0.1" in gateways


def test_runtime_gateway_blocks_organizer_declared_private_target() -> None:
    # RH3: 172.19.0.1 is not in the static list, but if it is a real runtime
    # gateway it must be rejected even with organizer_declared=true.
    inspect = '[{"IPAM": {"Config": [{"Gateway": "172.19.0.1"}]}}]'
    gateways = collect_docker_gateways(runner=_fake_network_runner(inspect))
    with pytest.raises(NetworkPolicyError, match="gateway"):
        parse_remotes(
            [{"host": "172.19.0.1", "port": 8080, "protocol": "tcp", "organizer_declared": True}],
            blocked_gateways=gateways,
        )


def test_non_gateway_private_target_still_allowed_with_runtime_set() -> None:
    inspect = '[{"IPAM": {"Config": [{"Gateway": "172.19.0.1"}]}}]'
    gateways = collect_docker_gateways(runner=_fake_network_runner(inspect))
    # A genuine organizer private target that is not any runtime gateway resolves.
    declared = parse_remotes(
        [{"host": "10.8.0.5", "port": 31337, "protocol": "tcp", "organizer_declared": True}],
        blocked_gateways=gateways,
    )
    assert declared[0].host == "10.8.0.5"


def test_cgnat_target_requires_explicit_organizer_declaration() -> None:
    with pytest.raises(NetworkPolicyError, match="organizer_declared"):
        parse_remotes(
            [{"host": "100.64.0.42", "port": 31337, "protocol": "tcp"}]
        )


def test_cgnat_target_is_allowed_when_explicitly_organizer_declared() -> None:
    declared = parse_remotes(
        [{
            "host": "100.64.0.42",
            "port": 31337,
            "protocol": "tcp",
            "organizer_declared": True,
        }]
    )
    assert declared[0].host == "100.64.0.42"


@pytest.mark.parametrize(
    ("host", "message"),
    (
        ("::ffff:169.254.169.254", "metadata"),
        ("::ffff:172.17.0.1", "gateway"),
    ),
)
def test_ipv4_mapped_ipv6_cannot_bypass_always_forbidden_targets(
    host: str,
    message: str,
) -> None:
    with pytest.raises(NetworkPolicyError, match=message):
        parse_remotes([{
            "host": host,
            "port": 80,
            "protocol": "http",
            "organizer_declared": True,
        }])


def test_collect_docker_gateways_malformed_inspect_fails_closed() -> None:
    with pytest.raises(NetworkPolicyError, match="malformed"):
        collect_docker_gateways(runner=_fake_network_runner("{not json"))


def test_collect_docker_gateways_inspect_failure_fails_closed() -> None:
    with pytest.raises(NetworkPolicyError, match="inspect failed"):
        collect_docker_gateways(runner=_fake_network_runner("[]", inspect_code=1))


def test_collect_docker_gateways_ls_failure_fails_closed() -> None:
    def runner(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 1, "", "daemon down")

    with pytest.raises(NetworkPolicyError, match="list Docker networks"):
        collect_docker_gateways(runner=runner)


def test_target_identity_dedupes_multi_ip_declared_target() -> None:
    metadata = {
        "challenge_id": "abc",
        "target_identities": ["nc ctf.example 31337", "nc ctf.example 31337"],
    }
    # A single logical declared target, even though stored twice (two IPs).
    assert _target_identity(metadata, None) == "nc ctf.example 31337"


def test_firewall_packets_sums_all_ips_of_one_declared_target(monkeypatch) -> None:
    metadata = {
        "name": "ctf-os-run-lane",
        "challenge_id": "abc",
        "authorized_targets": [
            {"declared": "https://ctf.example", "ip": "203.0.113.10", "port": 443},
            {"declared": "https://ctf.example", "ip": "203.0.113.11", "port": 443},
        ],
        "service_endpoints": [],
    }
    saved = (
        "[7:0] -A OUTPUT -d 203.0.113.10/32 -p tcp --dport 443 -j ACCEPT\n"
        "[5:0] -A OUTPUT -d 203.0.113.11/32 -p tcp --dport 443 -j ACCEPT\n"
    )

    def fake_run(argv, **kwargs):
        if "iptables-save" in argv:
            return subprocess.CompletedProcess(argv, 0, saved, "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(runtime_module.subprocess, "run", fake_run)
    # 7 + 5 packets across both A records of the same declared identity.
    assert firewall_packets(metadata, "https://ctf.example") == 12
