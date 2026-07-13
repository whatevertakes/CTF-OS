from pathlib import Path
import subprocess

import pytest

from ctf_os.sandbox.network import NetworkPolicyError, Target, parse_remotes
from ctf_os.sandbox.runtime import SandboxError, SandboxSpec, build_run_argv
import ctf_os.sandbox.runtime as runtime


def test_sandbox_argv_has_ro_source_limits_and_no_host_socket(tmp_path: Path) -> None:
    source = tmp_path / "input"
    source.mkdir()
    branch = tmp_path / "output" / "workers" / "recon"
    spec = SandboxSpec("demo", "abc123", "recon", source, branch)
    argv = build_run_argv(spec)
    joined = " ".join(argv)
    assert "dst=/challenge,readonly" in joined
    assert "--read-only" in argv and "--memory" in argv and "--cpus" in argv and "--pids-limit" in argv
    assert "/work:rw" in joined and "/artifacts:rw" in joined
    assert "docker.sock" not in joined and "--network none" in joined
    assert "team" not in joined and "member" not in joined


def test_authorized_url_and_nc_parse_and_private_targets_fail() -> None:
    targets = parse_remotes(("https://example.com/path", "nc 8.8.8.8 31337"))
    assert [(target.scheme, target.port) for target in targets] == [("https", 443), ("nc", 31337)]
    with pytest.raises(NetworkPolicyError):
        parse_remotes(("http://127.0.0.1",))
    with pytest.raises(NetworkPolicyError):
        parse_remotes(("nc metadata.google.internal 80",))


def test_branch_and_source_scope_are_validated(tmp_path: Path) -> None:
    with pytest.raises(SandboxError):
        build_run_argv(SandboxSpec("demo", "id", "../bad", tmp_path / "missing", tmp_path / "out"))


def test_dockerfile_has_no_nested_container_codex_or_unpinned_clone() -> None:
    text = Path("sandbox/Dockerfile.sandbox").read_text().casefold()
    for forbidden in ("podman", "buildah", "git clone", "codex", "|| echo"):
        assert forbidden not in text
    assert "ctf_os_profile=base" in text and "rev-heavy) packages=" in text


def test_remote_counters_only_count_exact_authorized_accept_rule(monkeypatch) -> None:
    output = "\n".join([
        "[99:999] -A OUTPUT -o lo -j ACCEPT",
        "[7:700] -A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
        "[3:300] -A OUTPUT -d 8.8.8.8/32 -p tcp -m tcp --dport 443 -j ACCEPT",
        "[55:5500] -A OUTPUT -j DROP",
    ])
    outputs = iter((output, ""))
    monkeypatch.setattr(runtime, "_run", lambda *args, **kwargs: subprocess.CompletedProcess([], 0, next(outputs), ""))
    counters = runtime._firewall_counters("container", "docker", [{"ip": "8.8.8.8", "port": 443}])
    assert counters == {"target_packets": 3, "established_packets": 7}
