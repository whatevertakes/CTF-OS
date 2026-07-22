from pathlib import Path
import subprocess

import pytest

from ctf_os.sandbox.network import NetworkPolicyError, Target, parse_remotes, resolve_targets
import ctf_os.sandbox.network as network
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
    assert "/work:rw" in joined and "/evidence:rw" in joined
    assert "dst=/context,readonly" in joined and "/artifacts:rw" in joined
    assert "docker.sock" not in joined and "--network none" in joined
    assert "team" not in joined and "member" not in joined


def test_workers_receive_distinct_durable_private_paths(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "input"
    source.mkdir()
    roots = [tmp_path / "output" / "workers" / branch for branch in ("worker-001", "worker-002")]
    monkeypatch.setattr(runtime, "admit", lambda *args, **kwargs: None)
    monkeypatch.setattr(runtime, "_run", lambda *args, **kwargs: subprocess.CompletedProcess([], 0, "id", ""))

    metadata = [runtime.create(SandboxSpec(
        "demo", "abc123", root.name, source, root,
        session_id=root.name, parent_session_id="sol-main", session_role="child",
    )) for root in roots]

    assert metadata[0]["work_path"] != metadata[1]["work_path"]
    for root in roots:
        assert all((root / name).is_dir() for name in ("work", "evidence", "logs", "context"))
        context = (root / "context" / "session.json").read_text()
        assert '"read_only": true' in context and '"private": true' in context
        assert (root / "context" / "session.json").stat().st_mode & 0o777 == 0o444
    (roots[0] / "work" / "proof.txt").write_text("one")
    assert not (roots[1] / "work" / "proof.txt").exists()


def test_service_connectivity_probe_uses_declared_stable_alias(monkeypatch) -> None:
    commands = []

    def fake_execute(metadata, command, timeout, docker="docker"):
        commands.append(command)
        return {"exit_code": 0, "stdout": "CTF_OS_SERVICE_CONNECTED challenge-service 8080\n", "stderr": ""}

    monkeypatch.setattr(runtime, "execute", fake_execute)
    result = runtime.probe_service_connectivity({"local_endpoints": ["http://challenge-service:8080"]})

    assert result == {"endpoint": "http://challenge-service:8080", "host": "challenge-service", "port": 8080, "connected": True}
    assert commands[0][-2:] == ["challenge-service", "8080"]


def test_service_sandbox_installs_service_only_network_policy(tmp_path: Path) -> None:
    source = tmp_path / "input"
    source.mkdir()
    spec = SandboxSpec(
        "demo", "abc123", "worker-001", source, tmp_path / "workers" / "worker-001",
        service_network="ctf-os-net-demo", local_endpoints=("http://challenge-service:3000",),
    )
    argv = build_run_argv(spec)
    entrypoint = Path("sandbox/entrypoint.sh").read_text()

    assert argv[argv.index("--network") + 1] == "ctf-os-net-demo"
    assert "NET_ADMIN" in argv
    assert "apply_local_firewall" in entrypoint
    assert "CTF_OS_LOCAL_ENDPOINTS_JSON" in entrypoint


def test_child_cannot_operate_a_sibling_sandbox(tmp_path: Path) -> None:
    metadata = {
        "session_id": "worker-001", "parent_session_id": "sol-main",
        "branch_root": str(tmp_path), "name": "ctf-os-worker-001",
    }
    with pytest.raises(SandboxError, match="DENIED_SANDBOX_ACCESS"):
        runtime.execute(metadata, ["true"], 1, session_id="worker-002", session_role="child")
    # The parent controller remains able to operate every child sandbox.
    runtime._authorize_sandbox(metadata, "sol-main", "sol", "execute")


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


def test_dockerfile_has_ten_profiles_and_no_nested_daemon_or_unpinned_clone() -> None:
    text = Path("sandbox/Dockerfile.sandbox").read_text().casefold()
    for forbidden in ("docker.sock", "git clone", "codex", "|| true", "|| echo"):
        assert forbidden not in text
    assert "ctf_os_profile=base" in text
    for profile in ("base", "pwn", "web", "rev", "crypto", "forensic", "misc", "osint", "ai", "cloud"):
        assert f"profile-{profile}" in text


def test_binary_runtime_is_shared_and_executes_dynamic_foreign_fixtures() -> None:
    dockerfile = Path("sandbox/Dockerfile.sandbox").read_text()
    installer = Path("sandbox/install/binary-runtime.sh").read_text()
    smoke = Path("sandbox/smoke/binary-runtime.sh").read_text()
    pwn = Path("sandbox/install/pwn.sh").read_text()
    rev = Path("sandbox/install/rev.sh").read_text()

    assert dockerfile.count("sandbox/install/binary-runtime.sh") == 2
    assert "/opt/ctf-os/install/binary-runtime.sh" in pwn
    assert "/opt/ctf-os/install/binary-runtime.sh" in rev
    for value in (
        "gcc-12-multilib", "libc6-dev-i386", "gcc-aarch64-linux-gnu",
        "gcc-arm-linux-gnueabihf", "gcc-mipsel-linux-gnu",
        "gcc-riscv64-linux-gnu", "libc6-dev-arm64-cross",
        "libc6-dev-armhf-cross", "libc6-dev-mipsel-cross",
        "libc6-dev-riscv64-cross",
    ):
        assert value in installer
    for value in (
        "gcc -m32", "qemu-aarch64 -L /usr/aarch64-linux-gnu",
        "qemu-arm -L /usr/arm-linux-gnueabihf",
        "qemu-mipsel -L /usr/mipsel-linux-gnu",
        "qemu-riscv64 -L /usr/riscv64-linux-gnu", "CTF_OS_QEMU_OK",
        "dynamically linked",
    ):
        assert value in smoke


def test_profile_installers_pin_requested_cli_capabilities_and_smokes() -> None:
    lib = Path("sandbox/install/lib.sh").read_text()
    binary = Path("sandbox/install/binary-analysis.sh").read_text()
    pwn = Path("sandbox/install/pwn.sh").read_text()
    pwn_fuzzing = Path("sandbox/install/pwn-fuzzing.sh").read_text()
    rev = Path("sandbox/install/rev.sh").read_text()
    web = Path("sandbox/install/web.sh").read_text()
    lock = Path("sandbox/tool-versions.lock").read_text()
    web_smoke = Path("sandbox/smoke/web-runtime.py").read_text()
    qemu_smoke = Path("sandbox/smoke/system-qemu.sh").read_text()
    dockerfile = Path("sandbox/Dockerfile.sandbox").read_text()

    assert "download_sha256()" in lib and "sha256sum --check --strict" in lib
    assert "pwninit=3.3.1" in lock and "pwninit_sha256=" in lock
    assert "seccomp_tools=1.6.2" in lock and "ffuf=2.1.0" in lock
    assert "download_sha256" in pwn and "musl-tools" in pwn
    assert "FROM common AS binary-analysis" in dockerfile
    assert "FROM binary-analysis AS pwn-tools" in dockerfile
    assert "FROM pwn-tools AS profile-pwn" in dockerfile
    assert "FROM binary-analysis AS profile-rev" in dockerfile
    for value in (
        "GHIDRA_VERSION=12.1.2", "TEMURIN_VERSION=21.0.11_10",
        "CAPA_VERSION=9.4.0", "CAPA_RULES_COMMIT=", "download_sha256",
    ):
        assert value in binary
    for value in (
        "AFLPP_COMMIT=", "QEMUAFL_COMMIT=", "afl-clang-fast",
        "afl-qemu-trace",
    ):
        assert value in pwn_fuzzing
    assert "ctf-os-pwn-fuzzing-smoke" in dockerfile
    assert "gem install seccomp-tools --version" in pwn
    for package in (
        "qemu-system-x86", "qemu-system-arm", "qemu-system-misc", "qemu-utils",
        "ovmf", "qemu-efi-aarch64", "qemu-efi-arm", "seabios", "u-boot-qemu",
    ):
        assert package in rev
    assert "github.com/ffuf/ffuf/v2@v${FFUF_VERSION}" in web
    for value in (
        "NUCLEI_VERSION=3.11.0", "NUCLEI_TEMPLATES_COMMIT=",
        "DALFOX_VERSION=3.1.2",
    ):
        assert value in web
    assert "ctf-os-web-security-smoke" in dockerfile
    assert all(package in web for package in ("chromium", "chromium-driver", "golang-go"))
    assert "executable_path=\"/usr/bin/chromium\"" in web_smoke
    assert "os.geteuid() == 0" in web_smoke
    assert "-machine none" in qemu_smoke and "status\" -ne 124" in qemu_smoke


def test_security_tool_assets_are_offline_bounded_and_pinned() -> None:
    lock = Path("sandbox/tool-versions.lock").read_text()
    nuclei_wrapper = Path("sandbox/bin/ctf-nuclei-scan").read_text()
    ghidra_wrapper = Path("sandbox/bin/ctf-ghidra-headless").read_text()
    semgrep_rules = Path("sandbox/rules/semgrep/ctf-web-sinks.yml").read_text()
    ai_smoke = Path("sandbox/smoke/ai-serialization.py").read_text()
    afl_smoke = Path("sandbox/smoke/pwn-fuzzing.sh").read_text()

    for key in (
        "ghidra_sha256=", "capa_rules_sha256=", "aflplusplus_sha256=",
        "qemuafl_sha256=", "nuclei_sha256=", "nuclei_templates_sha256=",
        "dalfox_sha256=", "sqlmap_wheel_sha256=", "semgrep_wheel_sha256=",
        "modelscan_wheel_sha256=", "fickling_wheel_sha256=",
    ):
        assert key in lock
    assert "-disable-update-check" in nuclei_wrapper
    assert "-no-interactsh" in nuclei_wrapper and "-pt http" in nuclei_wrapper
    assert "/artifacts/" in nuclei_wrapper and "one explicit HTTP(S) URL" in nuclei_wrapper
    assert "/work/ghidra-project" in ghidra_wrapper and "/artifacts/" in ghidra_wrapper
    for language in ("python", "javascript", "typescript", "php", "java"):
        assert language in semgrep_rules
    assert "pickle.loads" not in ai_smoke and "torch.load" not in ai_smoke
    assert "not marker.exists()" in ai_smoke
    for value in ("afl-clang-fast", "afl-showmap", "AFL_USE_ASAN", "AFL_USE_UBSAN", "-Q"):
        assert value in afl_smoke


def test_runtime_isolates_mutable_credentials_in_work_tmpfs(tmp_path: Path) -> None:
    source = tmp_path / "input"
    source.mkdir()
    argv = build_run_argv(SandboxSpec("demo", "id", "cloud", source, tmp_path / "out", image="ctf-os-sandbox:cloud"))
    joined = " ".join(argv)
    for forbidden in (".aws", ".azure", ".config/gcloud", "kubeconfig", "/dev/kvm", "/dev/nvidia", "--privileged", "--network host", "--pid host"):
        assert forbidden not in joined
    assert "seccomp-rootless.json" in joined
    profile = Path("sandbox/seccomp-rootless.json").read_text(encoding="utf-8")
    assert '"defaultAction": "SCMP_ACT_ERRNO"' in profile
    assert '"mount"' in profile


def test_rootless_seccomp_is_not_added_to_ordinary_profiles(tmp_path: Path) -> None:
    source = tmp_path / "input"
    source.mkdir()
    argv = build_run_argv(SandboxSpec("demo", "id", "pwn", source, tmp_path / "out", image="ctf-os-sandbox:pwn"))
    assert "seccomp-rootless.json" not in " ".join(argv)


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
    assert counters == {
        "target_packets": 3, "target_packets_by_index": [3],
        "established_packets": 7,
    }


def test_dns_multi_address_and_change_are_resolved_per_sandbox(monkeypatch) -> None:
    target = parse_remotes(("https://fixture.example/path",))[0]
    answers = iter((
        [
            (2, 1, 6, "", ("1.1.1.1", 443)),
            (10, 1, 6, "", ("2606:4700:4700::1111", 443, 0, 0)),
        ],
        [(2, 1, 6, "", ("8.8.8.8", 443))],
    ))
    monkeypatch.setattr(network.socket, "getaddrinfo", lambda *args, **kwargs: next(answers))

    first = resolve_targets((target,))
    second = resolve_targets((target,))

    assert {item.address for item in first} == {"1.1.1.1", "2606:4700:4700::1111"}
    assert [item.address for item in second] == ["8.8.8.8"]
