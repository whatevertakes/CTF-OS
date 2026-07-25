from __future__ import annotations

import json
import os
import subprocess
import time
import zipfile
from pathlib import Path

import pytest
from conftest import fake_sandbox, make_race

import ctf_os.service as service_module
from ctf_os.archive import ArchiveError, extract_archive
from ctf_os.preflight import detect_service
from ctf_os.sandbox.network import (
    NetworkPolicyError,
    ResolvedTarget,
    Target,
    parse_remotes,
)
from ctf_os.sandbox.runtime import (
    USER_EXEC_ENV,
    SandboxError,
    SandboxSpec,
    argv_family,
    build_run_argv,
    cleanup,
    execute,
    user_exec_prefix,
)
from ctf_os.sandbox.session import (
    SessionError,
    close_session,
    list_tools,
    open_session,
    tool_help,
    tool_version,
)
from ctf_os.sandbox.session import (
    read as session_read,
)
from ctf_os.service import (
    ServiceActor,
    ServiceCleanupError,
    ServiceError,
    ServiceSpec,
    cleanup_service,
    prepare_service,
)

_ALL_IMAGE_PROFILES = (
    "base", "pwn", "web", "rev", "crypto",
    "forensic", "misc", "osint", "ai", "cloud",
)


def _live_image_profiles() -> tuple[str, ...]:
    requested = tuple(os.environ.get("CTF_OS_LIVE_PROFILES", "").split())
    if not requested:
        return _ALL_IMAGE_PROFILES
    unknown = set(requested).difference(_ALL_IMAGE_PROFILES)
    if unknown:
        raise ValueError(f"unknown CTF_OS_LIVE_PROFILES: {sorted(unknown)}")
    return requested


def _podman_sandbox_spec(tmp_path: Path, category: str) -> SandboxSpec:
    root = tmp_path / category
    source = root / "input"
    source.mkdir(parents=True)
    source.chmod(0o555)
    lane_root = root / "workers" / "root"
    for name in ("work", "evidence", "artifacts", "context"):
        path = lane_root / name
        path.mkdir(parents=True, exist_ok=True)
        path.chmod(0o755 if name == "context" else 0o777)
    return SandboxSpec(
        run_id=f"run-{category}",
        contest_slug="demo",
        challenge_id="challenge1",
        category=category,
        lane_id="root",
        source=source,
        lane_root=lane_root,
        input_fingerprint="0" * 64,
        image=f"ctf-os-sandbox:{category}",
    )


def test_sandbox_has_read_only_input_private_writable_paths_and_no_host_credentials(tmp_path: Path) -> None:
    source = tmp_path / "input"
    source.mkdir()
    source.chmod(0o555)
    target = ResolvedTarget(Target("nc ctf.example 31337", "ctf.example", 31337, "nc"), "203.0.113.10")
    spec = SandboxSpec(
        run_id="run-1", contest_slug="demo", challenge_id="challenge1", category="pwn",
        lane_id="root", source=source, lane_root=tmp_path / "workers" / "root",
        input_fingerprint="0" * 64, image="ctf-os-sandbox:pwn", targets=(target,),
    )
    for name in ("work", "evidence", "artifacts", "context"):
        (spec.lane_root / name).mkdir(parents=True, exist_ok=True)
    argv = build_run_argv(spec)
    joined = " ".join(argv)
    assert f"src={source.resolve()},dst=/challenge,readonly" in joined
    assert "dst=/work" in joined and "dst=/evidence" in joined and "dst=/artifacts" in joined
    assert "/home/ctf/.cache:rw,nosuid,nodev,size=256m,mode=0700,uid=1001,gid=1001" in argv
    assert "/var/run/docker.sock" not in joined
    for forbidden in (".ssh", "kubeconfig", ".aws", "chrome", "host.docker.internal"):
        assert forbidden not in joined.casefold()
    assert "--network bridge" in joined
    assert "CTF_OS_ALLOWED_ENDPOINTS_JSON" in joined
    assert joined.count("--cap-add CHOWN") == 1
    assert joined.count("--cap-add DAC_READ_SEARCH") == 1


@pytest.mark.parametrize(
    ("category", "expects_rootless_seccomp"),
    (("cloud", True), ("misc", True), ("web", False)),
)
def test_rootless_podman_seccomp_is_scoped_to_advertised_categories(
    tmp_path: Path,
    category: str,
    expects_rootless_seccomp: bool,
) -> None:
    argv = build_run_argv(_podman_sandbox_spec(tmp_path, category))
    seccomp = (
        Path(__file__).resolve().parents[1] / "sandbox" / "seccomp-rootless.json"
    )
    security_opt = f"seccomp={seccomp}"
    assert (security_opt in argv) is expects_rootless_seccomp


def test_user_docker_exec_prefix_carries_only_lane_private_state(
    repo: Path,
) -> None:
    _manifest, challenge, run, _race = make_race(repo, category="cloud")
    metadata = fake_sandbox(
        run, challenge, "root", "ctf-os-sandbox:cloud",
    )
    argv = user_exec_prefix(
        metadata,
        interactive=True,
        detach=True,
        workdir="/work",
    )
    assert argv[:6] == [
        "docker", "exec", "--interactive", "--detach", "--user", "1001:1001",
    ]
    assert "--workdir" in argv
    for value in USER_EXEC_ENV:
        assert argv.count(value) == 1
        assert argv[argv.index(value) - 1] == "--env"
        assert "/work" in value.split("=", 1)[1]
    joined = " ".join(argv).casefold()
    for forbidden in (
        str(repo.resolve()).casefold(),
        ".ssh",
        "host.docker.internal",
    ):
        assert forbidden not in joined


def test_metadata_gateways_private_networks_and_undeclared_targets_are_rejected() -> None:
    for value in ("169.254.169.254:80", "172.17.0.1:80", "localhost:80", "10.0.0.5:1234"):
        with pytest.raises(NetworkPolicyError):
            parse_remotes([value])
    declared = parse_remotes([{"host": "10.0.0.5", "port": 31337, "protocol": "tcp", "organizer_declared": True}])
    assert declared[0].organizer_declared is True


def test_archive_traversal_and_links_never_enter_prepared_input(tmp_path: Path) -> None:
    archive = tmp_path / "challenge.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("../escape", "bad")
    destination = tmp_path / "prepared"
    destination.mkdir()
    with pytest.raises(ArchiveError, match="traversal"):
        extract_archive(archive, destination)
    assert not (tmp_path / "escape").exists()


def test_dangerous_compose_is_blocked_before_service_lifecycle(tmp_path: Path) -> None:
    input_root = tmp_path / "input"
    input_root.mkdir()
    (input_root / "compose.yml").write_text(
        "services:\n  chall:\n    image: demo\n    privileged: true\n    network_mode: host\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n",
        encoding="utf-8",
    )
    plan = detect_service(input_root, "web")
    assert plan["safe"] is False
    assert any("Docker socket" in reason for reason in plan["review_reasons"])


@pytest.mark.parametrize(
    "fragment",
    (
        "    use_api_socket: true\n",
        "    volumes_from: [other]\n",
        "    logging: {driver: syslog, options: {syslog-address: tcp://127.0.0.1:1}}\n",
        "    security_opt: [seccomp=unconfined]\n",
        "    volumes: ['${PWD}:/host']\n",
        "    extends: {file: ../../host.yml, service: other}\n",
    ),
)
def test_compose_host_and_daemon_escape_surfaces_are_rejected(
    tmp_path: Path, fragment: str
) -> None:
    input_root = tmp_path / "input"
    input_root.mkdir()
    (input_root / "compose.yml").write_text(
        "services:\n  chall:\n    image: demo\n    expose: [8000]\n" + fragment,
        encoding="utf-8",
    )
    plan = detect_service(input_root, "web")
    assert plan["safe"] is False
    assert plan["review_reasons"]


@pytest.mark.parametrize(
    "fragment",
    (
        "    environment: [AWS_SECRET_ACCESS_KEY]\n",
        "    environment: {AWS_SECRET_ACCESS_KEY: null}\n",
        "    environment: {TOKEN: '${AWS_SECRET_ACCESS_KEY}'}\n",
        "    command: ['sh', '-c', 'printf %s ${AWS_SECRET_ACCESS_KEY}']\n",
    ),
)
def test_compose_cannot_inherit_or_interpolate_controller_environment(
    tmp_path: Path, fragment: str
) -> None:
    input_root = tmp_path / "input"
    input_root.mkdir()
    (input_root / "compose.yml").write_text(
        "services:\n  chall:\n    image: demo\n    expose: [8000]\n" + fragment,
        encoding="utf-8",
    )

    plan = detect_service(input_root, "web")

    assert plan["safe"] is False
    assert any(
        "environment" in reason.casefold() or "interpolation" in reason.casefold()
        for reason in plan["review_reasons"]
    )


def test_compose_literal_environment_and_escaped_container_dollar_are_allowed(
    tmp_path: Path,
) -> None:
    input_root = tmp_path / "input"
    input_root.mkdir()
    (input_root / "compose.yml").write_text(
        "services:\n"
        "  chall:\n"
        "    image: demo\n"
        "    expose: [8000]\n"
        "    environment: [MODE=challenge]\n"
        "    command: ['sh', '-c', 'printf %s $$HOME']\n",
        encoding="utf-8",
    )

    plan = detect_service(input_root, "web")

    assert plan["safe"] is True
    assert plan["review_reasons"] == []


def test_compose_named_volume_driver_opts_cannot_bind_host(tmp_path: Path) -> None:
    input_root = tmp_path / "input"
    input_root.mkdir()
    (input_root / "compose.yml").write_text(
        "services:\n  chall:\n    image: demo\n    expose: [8000]\n"
        "    volumes: [data:/data]\n"
        "volumes:\n  data:\n    driver: local\n"
        "    driver_opts: {type: none, o: bind, device: /}\n",
        encoding="utf-8",
    )
    plan = detect_service(input_root, "web")
    assert plan["safe"] is False
    assert any("custom driver" in reason for reason in plan["review_reasons"])


def test_oversized_service_descriptor_is_rejected_without_parsing(
    tmp_path: Path
) -> None:
    input_root = tmp_path / "input"
    input_root.mkdir()
    (input_root / "compose.yml").write_bytes(b" " * (1024 * 1024 + 1))
    plan = detect_service(input_root, "web")
    assert plan["safe"] is False
    assert any("exceeds" in reason for reason in plan["review_reasons"])


def test_compose_build_context_cannot_escape_prepared_input(tmp_path: Path) -> None:
    input_root = tmp_path / "input"
    input_root.mkdir()
    (input_root / "compose.yml").write_text(
        "services:\n  chall:\n    build: ../../\n    expose: [8000]\n",
        encoding="utf-8",
    )
    plan = detect_service(input_root, "web")
    assert plan["safe"] is False
    assert any("build context escapes" in reason for reason in plan["review_reasons"])


def test_dockerfile_without_declared_port_is_not_misclassified_as_a_service(tmp_path: Path) -> None:
    input_root = tmp_path / "input"
    input_root.mkdir()
    (input_root / "Dockerfile").write_text("FROM scratch\nCOPY chall /chall\n", encoding="utf-8")
    plan = detect_service(input_root, "rev")
    assert plan["kind"] == "none"
    assert plan["safe"] is True


def test_compose_override_resets_host_ports_and_networks(
    tmp_path: Path, monkeypatch
) -> None:
    input_root = tmp_path / "input"
    input_root.mkdir()
    (input_root / "compose.yml").write_text(
        "services:\n  chall:\n    image: ctf-os-sandbox:base\n    ports: ['127.0.0.1:18000:8000']\n",
        encoding="utf-8",
    )
    plan = detect_service(input_root, "web")
    for path in input_root.rglob("*"):
        path.chmod(0o444 if path.is_file() else 0o555)
    input_root.chmod(0o555)
    calls: list[tuple[list[str], dict]] = []
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "host-secret-must-not-cross")
    monkeypatch.setenv("CTF_OS_SYNTHETIC_SENTINEL", "host-only")

    def runner(argv, **kwargs):
        calls.append((list(argv), dict(kwargs)))
        if argv[1:2] == ["info"]:
            return subprocess.CompletedProcess(
                argv, 0,
                json.dumps({"MemTotal": 32 * 1024**3, "NCPU": 16}),
                "",
            )
        if argv[1:2] == ["ps"] and "--status" not in argv:
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[1:3] == ["network", "inspect"]:
            return subprocess.CompletedProcess(argv, 1, "", "not found")
        if "config" in argv and "--format" in argv:
            return subprocess.CompletedProcess(
                argv, 0,
                json.dumps({"services": {"chall": {"image": "ctf-os-sandbox:base"}}}),
                "",
            )
        if "ps" in argv and "--status" in argv:
            return subprocess.CompletedProcess(argv, 0, "container-id\n", "")
        return subprocess.CompletedProcess(argv, 0, "[]", "")

    spec = ServiceSpec(
        run_id="run-compose", challenge_id="challenge1", source=input_root,
        run_root=tmp_path / "run", plan=plan,
    )
    metadata = prepare_service(spec, actor=ServiceActor("root", "root"), runner=runner)
    override = Path(metadata["runtime"]["compose_files"][1]).read_text(encoding="utf-8")
    assert "ports: !reset []" in override
    assert "networks: !reset" in override
    assert any(
        argv[1:3] == ["network", "create"] and "--internal" in argv
        for argv, _kwargs in calls
    )
    compose_up, compose_kwargs = next(
        (argv, kwargs) for argv, kwargs in calls if "up" in argv
    )
    assert compose_up[-2:] == ["--pull", "never"]
    assert "--env-file" in compose_up
    empty_env = Path(compose_up[compose_up.index("--env-file") + 1])
    assert empty_env.read_text(encoding="utf-8") == ""
    controller_env = compose_kwargs["env"]
    assert "AWS_SECRET_ACCESS_KEY" not in controller_env
    assert "CTF_OS_SYNTHETIC_SENTINEL" not in controller_env
    assert Path(controller_env["HOME"]).is_relative_to(spec.metadata_path.parent)
    assert Path(controller_env["DOCKER_CONFIG"]).is_relative_to(
        spec.metadata_path.parent
    )


def test_flag_candidate_forces_a_term_ignoring_exec_to_finish_promptly(
    tmp_path: Path,
) -> None:
    lane_root = tmp_path / "workers" / "root"
    lane_root.mkdir(parents=True)
    fake_docker = tmp_path / "fake-docker"
    fake_docker.write_text(
        "#!/bin/sh\n"
        "for arg in \"$@\"; do\n"
        "  [ \"$arg\" = ctf-os-kill ] && exit 0\n"
        "done\n"
        "trap '' TERM\n"
        "printf 'ACTF{prompt_flag}\\n'\n"
        "exec sleep 3\n",
        encoding="utf-8",
    )
    fake_docker.chmod(0o755)
    metadata = {
        "name": "ctf-os-run-root",
        "run_id": "run",
        "challenge_id": "challenge1",
        "lane_id": "root",
        "lane_root": str(lane_root),
        "target_identities": ["challenge:challenge1"],
    }

    started = time.monotonic()
    receipt = execute(
        metadata,
        ["solver"],
        candidate_probe=lambda output: (
            "ACTF{prompt_flag}" if "ACTF{prompt_flag}" in output else None
        ),
        docker=str(fake_docker),
    )
    elapsed = time.monotonic() - started

    assert receipt["flag_candidate"] == "ACTF{prompt_flag}"
    assert elapsed < 1.5


def test_shell_argv_family_uses_inner_command_shape_not_payload_arguments() -> None:
    first = argv_family(
        ["bash", "-lc", "python3 /work/solve.py --mode one"]
    )
    second = argv_family(
        ["bash", "-lc", "python3 /work/solve.py --mode two"]
    )
    different_tool = argv_family(
        ["bash", "-lc", "node /work/solve.js --mode one"]
    )

    assert first == second
    assert "one" not in first and "two" not in second
    assert first != different_tool


def test_service_metadata_failure_exposes_structured_cleanup_recovery(
    tmp_path: Path, monkeypatch
) -> None:
    input_root = tmp_path / "input"
    input_root.mkdir()
    (input_root / "compose.yml").write_text(
        "services:\n"
        "  chall:\n"
        "    image: ctf-os-sandbox:base\n"
        "    expose: [8000]\n",
        encoding="utf-8",
    )
    plan = detect_service(input_root, "web")
    for path in input_root.rglob("*"):
        path.chmod(0o444 if path.is_file() else 0o555)
    input_root.chmod(0o555)
    network_created = False

    def runner(argv, **_kwargs):
        nonlocal network_created
        if argv[1:2] == ["info"]:
            return subprocess.CompletedProcess(
                argv, 0,
                json.dumps({"MemTotal": 32 * 1024**3, "NCPU": 16}),
                "",
            )
        if argv[1:2] == ["ps"] and "--status" not in argv:
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[1:3] == ["network", "create"]:
            network_created = True
            return subprocess.CompletedProcess(argv, 0, "network\n", "")
        if argv[1:3] == ["network", "inspect"]:
            if not network_created:
                return subprocess.CompletedProcess(argv, 1, "", "not found")
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps([{"Internal": True, "Labels": spec.labels}]),
                "",
            )
        if "config" in argv and "--format" in argv:
            return subprocess.CompletedProcess(
                argv, 0,
                json.dumps({"services": {"chall": {"image": "ctf-os-sandbox:base"}}}),
                "",
            )
        if "down" in argv:
            return subprocess.CompletedProcess(argv, 1, "", "compose down failed")
        if "ps" in argv and "--all" in argv:
            # RM3 ownership enumeration before teardown.
            return subprocess.CompletedProcess(argv, 0, "svc-container\n", "")
        if argv[1:2] == ["inspect"]:
            return subprocess.CompletedProcess(
                argv, 0, json.dumps([{"Config": {"Labels": spec.labels}}]), ""
            )
        if "ps" in argv and "--status" in argv:
            return subprocess.CompletedProcess(argv, 0, "container-id\n", "")
        return subprocess.CompletedProcess(argv, 0, "[]", "")

    spec = ServiceSpec(
        run_id="run-compose-failure",
        challenge_id="challenge1",
        source=input_root,
        run_root=tmp_path / "run",
        plan=plan,
    )
    real_atomic_json = service_module.atomic_json

    def fail_service_metadata(path, payload):
        if path == spec.metadata_path:
            raise OSError("synthetic metadata write failure")
        real_atomic_json(path, payload)

    monkeypatch.setattr(service_module, "atomic_json", fail_service_metadata)

    with pytest.raises(ServiceCleanupError) as raised:
        prepare_service(
            spec,
            actor=ServiceActor("root", "root"),
            runner=runner,
        )

    assert raised.value.service["status"] == "CLEANUP_FAILED"
    assert raised.value.service["runtime"]["project"] == spec.project
    assert raised.value.failures == ("compose down failed",)


@pytest.mark.live
@pytest.mark.skipif(
    os.environ.get("CTF_OS_LIVE") != "1",
    reason="set CTF_OS_LIVE=1",
)
def test_live_compose_controller_environment_is_not_inherited(
    tmp_path: Path, monkeypatch
) -> None:
    input_root = tmp_path / "input"
    input_root.mkdir()
    (input_root / "compose.yml").write_text(
        "services:\n"
        "  chall:\n"
        "    image: ctf-os-sandbox:base\n"
        "    entrypoint: []\n"
        "    environment: [CTF_OS_SYNTHETIC_SENTINEL]\n"
        "    command:\n"
        "      - sh\n"
        "      - -ec\n"
        "      - test -z \"$$CTF_OS_SYNTHETIC_SENTINEL\"; "
        "exec python3 -m http.server 8000\n"
        "    expose: [8000]\n",
        encoding="utf-8",
    )
    input_root.chmod(0o555)
    (input_root / "compose.yml").chmod(0o444)
    monkeypatch.setenv("CTF_OS_SYNTHETIC_SENTINEL", "host-secret")
    spec = ServiceSpec(
        run_id="run-compose-live",
        challenge_id="challenge1",
        source=input_root,
        run_root=tmp_path / "run",
        plan={
            "kind": "compose",
            "safe": True,
            "source": "compose.yml",
            "base_images": [],
            "runtime_images": ["ctf-os-sandbox:base"],
            "services": [{
                "name": "chall",
                "ports": [8000],
                "endpoints": ["http://chall:8000"],
                "build": False,
            }],
            "review_reasons": [],
        },
    )
    metadata: dict | None = None

    try:
        metadata = prepare_service(
            spec,
            actor=ServiceActor("root", "root"),
        )
        assert metadata["status"] == "READY"
    finally:
        if metadata is not None:
            result = cleanup_service(
                metadata,
                actor=ServiceActor("root", "root"),
            )
            assert result["cleaned"] is True


def test_only_root_can_change_service_lifecycle(tmp_path: Path) -> None:
    source = tmp_path / "input"
    source.mkdir()
    source.chmod(0o555)
    spec = ServiceSpec(
        run_id="run-123", challenge_id="challenge1", source=source, run_root=tmp_path / "run",
        plan={"kind": "dockerfile", "safe": True, "source": "Dockerfile", "context": ".", "services": []},
    )
    with pytest.raises(ServiceError, match="only Root"):
        prepare_service(spec, actor=ServiceActor("lane-1", "child"))


def test_persistent_session_is_category_bounded_and_reads_receipted_output(repo: Path) -> None:
    _manifest, challenge, run, _race = make_race(repo, category="pwn")
    metadata = fake_sandbox(run, challenge, "root", "ctf-os-sandbox:pwn")
    calls: list[list[str]] = []

    def runner(argv, **kwargs):
        calls.append(list(argv))
        if "ctf-os-session-identity" in argv:
            return subprocess.CompletedProcess(argv, 0, "4242 99\n", "")
        if "python3" in argv and "-c" in argv:
            return subprocess.CompletedProcess(argv, 0, "gdb output\n", " 11\n")
        return subprocess.CompletedProcess(argv, 0, "", "")

    state = open_session(
        metadata, session_id="dbg-main", kind="debugger", command=["gdb", "-q", "/challenge/chall"], runner=runner
    )
    assert state["status"] == "RUNNING"
    assert state["pid"] == 4242
    assert state["pid_start_time"] == "99"
    assert any("ulimit -f 131072" in value for value in calls[0])
    assert all(value in calls[0] for value in USER_EXEC_ENV)
    receipt = session_read(metadata, session_id="dbg-main", runner=runner)
    assert receipt["observed_output"] == "gdb output\n"
    assert (run / "workers" / "root" / "logs" / f"{receipt['receipt_id']}.json").is_file()
    assert list_tools("pwn")["tools"]
    assert "gdb" in tool_help("pwn", "gdb")["hint"]

    pwndbg_state = open_session(
        metadata, session_id="dbg-pwndbg", kind="debugger",
        command=["pwndbg", "-q", "/challenge/chall"], runner=runner,
    )
    assert pwndbg_state["argv"][0] == "pwndbg"


def test_added_image_tools_are_exposed_by_category() -> None:
    expected = {
        "pwn": {"pwninit", "angrop"},
        "forensic": {"stegseek"},
        "misc": {"ares"},
        "crypto": {"ares"},
        "web": {"sstimap"},
        "osint": {"sherlock", "maigret", "holehe", "theHarvester"},
    }
    for category, tools in expected.items():
        assert tools <= set(list_tools(category)["tools"])
        for tool in tools:
            assert tool_help(category, tool)["hint"]


def test_catalog_uses_real_commands_and_does_not_advertise_missing_tools() -> None:
    assert "gdb" not in list_tools("base")["tools"]
    assert "gdb" not in list_tools("web")["tools"]
    assert "gdb" in list_tools("pwn")["tools"]
    assert "gdb" in list_tools("rev")["tools"]
    assert "pwndbg" in list_tools("pwn")["tools"]
    assert "ghidra" not in list_tools("rev")["tools"]
    assert "ctf-ghidra-headless" in list_tools("rev")["tools"]
    assert "volatility3" not in list_tools("forensic")["tools"]
    assert "vol" in list_tools("forensic")["tools"]
    assert "python3 -m pickletools" in tool_help("ai", "pickletools")["hint"]


def test_tool_version_uses_offline_safe_probe_for_python_only_tool(repo: Path) -> None:
    _manifest, challenge, run, _race = make_race(repo, category="pwn")
    metadata = fake_sandbox(run, challenge, "root", "ctf-os-sandbox:pwn")
    calls: list[list[str]] = []

    def runner(argv, **kwargs):
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, "9.2.12.post3\n", "")

    result = tool_version(metadata, "angrop", runner=runner)
    assert result == {"tool": "angrop", "available": True, "output": "9.2.12.post3\n"}
    assert calls[0][-3:-1] == ["python3", "-c"]
    assert "--version" not in calls[0]


@pytest.mark.parametrize(
    ("category", "name", "expected_tail"),
    [
        ("base", "nc", ("dpkg-query", "--show", "--showformat=${Version}\n", "netcat-openbsd")),
        ("pwn", "pwndbg", ("pwndbg", "--batch", "-q", "-ex", "pi import pwndbg; print(pwndbg.__version__)", "-ex", "quit")),
        ("web", "ffuf", ("ffuf", "-V")),
        ("rev", "ctf-ghidra-headless", ("sh", "-ec", "grep '^ghidra=' /opt/ctf-os/tool-versions.lock")),
        ("forensic", "vol", ("python3", "-c", "from importlib.metadata import version; print(version('volatility3'))")),
        ("ai", "onnxruntime", ("python3", "-c", "from importlib.metadata import version; print(version('onnxruntime-gpu'))")),
        ("cloud", "kubectl", ("kubectl", "version", "--client=true")),
    ],
)
def test_tool_version_uses_exact_probe_for_nonstandard_tools(
    repo: Path, category: str, name: str, expected_tail: tuple[str, ...]
) -> None:
    _manifest, challenge, run, _race = make_race(repo, category=category)
    metadata = fake_sandbox(run, challenge, "root", f"ctf-os-sandbox:{category}")
    calls: list[list[str]] = []

    def runner(argv, **kwargs):
        calls.append(list(argv))
        return subprocess.CompletedProcess(argv, 0, "version\n", "")

    assert tool_version(metadata, name, runner=runner)["available"] is True
    assert tuple(calls[0][-len(expected_tail):]) == expected_tail


def test_cleanup_does_not_remove_sandbox_when_ownership_normalization_fails() -> None:
    metadata = {
        "name": "ctf-os-run-root",
        "labels": {"org.ctf-os.run-id": "run-1"},
    }
    calls: list[list[str]] = []

    def runner(argv, **kwargs):
        calls.append(list(argv))
        if argv[1] == "inspect":
            return subprocess.CompletedProcess(
                argv, 0,
                json.dumps([{"Config": {"Labels": {"org.ctf-os.run-id": "run-1"}}}]),
                "",
            )
        if argv[1:4] == ["exec", "--user", "0:0"]:
            return subprocess.CompletedProcess(argv, 1, "", "permission denied")
        return subprocess.CompletedProcess(argv, 0, "", "")

    with pytest.raises(SandboxError, match="normalization failed"):
        cleanup(metadata, runner=runner)
    assert not any(argv[1:3] == ["rm", "--force"] for argv in calls)


def test_cleanup_requires_successful_chown_before_container_removal() -> None:
    metadata = {
        "name": "ctf-os-run-root",
        "labels": {"org.ctf-os.run-id": "run-1"},
    }
    calls: list[list[str]] = []

    def runner(argv, **kwargs):
        calls.append(list(argv))
        if argv[1] == "inspect":
            return subprocess.CompletedProcess(
                argv, 0,
                json.dumps([{"Config": {"Labels": {"org.ctf-os.run-id": "run-1"}}}]),
                "",
            )
        return subprocess.CompletedProcess(argv, 0, "", "")

    result = cleanup(metadata, runner=runner)
    assert result["host_ownership_normalized"] is True
    assert result["normalization_warning"] is None
    assert [argv[1] for argv in calls] == ["inspect", "exec", "rm"]
    assert calls[1][2:4] == ["--user", "0:0"]


def test_cleanup_restarts_stopped_sandbox_before_ownership_normalization() -> None:
    metadata = {
        "name": "ctf-os-run-root",
        "labels": {"org.ctf-os.run-id": "run-1"},
    }
    calls: list[list[str]] = []

    def runner(argv, **kwargs):
        calls.append(list(argv))
        if argv[1] == "inspect":
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps([{
                    "Config": {"Labels": {"org.ctf-os.run-id": "run-1"}},
                    "State": {"Running": False},
                }]),
                "",
            )
        return subprocess.CompletedProcess(argv, 0, "", "")

    result = cleanup(metadata, runner=runner)
    assert result["removed"] is True
    assert result["restarted_for_normalization"] is True
    assert [argv[1] for argv in calls] == ["inspect", "start", "exec", "rm"]


@pytest.mark.live
@pytest.mark.skipif(os.environ.get("CTF_OS_LIVE") != "1", reason="set CTF_OS_LIVE=1")
def test_live_cleanup_restarts_a_stopped_sandbox(tmp_path: Path) -> None:
    spec = _podman_sandbox_spec(tmp_path, "base")
    started = subprocess.run(
        build_run_argv(spec),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert started.returncode == 0, started.stdout + started.stderr
    try:
        stopped = subprocess.run(
            ["docker", "stop", spec.name],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert stopped.returncode == 0, stopped.stdout + stopped.stderr
        result = cleanup({"name": spec.name, "labels": spec.labels})
        assert result["removed"] is True
        assert result["host_ownership_normalized"] is True
        assert result["restarted_for_normalization"] is True
    finally:
        subprocess.run(
            ["docker", "rm", "--force", spec.name],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )


def test_cleanup_does_not_treat_docker_daemon_failure_as_absent() -> None:
    metadata = {
        "name": "ctf-os-run-root",
        "labels": {"org.ctf-os.run-id": "run-1"},
    }

    def runner(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 1, "", "daemon unavailable")

    with pytest.raises(SandboxError, match="inspection failed"):
        cleanup(metadata, runner=runner)


def test_failed_session_close_remains_retryable(repo: Path) -> None:
    _manifest, challenge, run, _race = make_race(repo, category="pwn")
    metadata = fake_sandbox(run, challenge, "root", "ctf-os-sandbox:pwn")

    def open_runner(argv, **kwargs):
        if "ctf-os-session-identity" in argv:
            return subprocess.CompletedProcess(argv, 0, "4242 99\n", "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    open_session(
        metadata,
        session_id="retry-close",
        kind="shell",
        command=["sh"],
        runner=open_runner,
    )

    def fail_runner(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 1, "", "docker exec failed")

    result = close_session(
        metadata, session_id="retry-close", runner=fail_runner
    )
    state = json.loads(
        (run / "workers" / "root" / "sessions" / "retry-close.json").read_text()
    )
    assert result["stopped"] is False
    assert state["status"] == "RUNNING"


@pytest.mark.live
@pytest.mark.skipif(os.environ.get("CTF_OS_LIVE") != "1", reason="set CTF_OS_LIVE=1")
def test_every_catalog_tool_has_a_working_version_probe(tmp_path: Path) -> None:
    for category in _live_image_profiles():
        suffix = abs(hash((str(tmp_path), category)))
        name = f"ctf-os-tool-catalog-{category}-{suffix:x}"[:63]
        started = subprocess.run(
            [
                "docker", "run", "--detach", "--rm", "--name", name,
                "--network", "none", f"ctf-os-sandbox:{category}", "sleep", "infinity",
            ],
            capture_output=True, text=True, timeout=60, check=False,
        )
        assert started.returncode == 0, started.stdout + started.stderr
        try:
            metadata = {"category": category, "name": name}
            for tool in list_tools(category)["tools"]:
                result = tool_version(metadata, tool)
                assert result["available"] is True, (
                    f"{category}/{tool}: {result['output']}"
                )
        finally:
            subprocess.run(
                ["docker", "rm", "--force", name],
                capture_output=True, text=True, timeout=30, check=False,
            )


@pytest.mark.live
@pytest.mark.skipif(os.environ.get("CTF_OS_LIVE") != "1", reason="set CTF_OS_LIVE=1")
@pytest.mark.parametrize("category", ("cloud", "misc"))
def test_rootless_podman_info_runs_in_hardened_catalog_sandbox(
    tmp_path: Path,
    category: str,
) -> None:
    if category not in _live_image_profiles():
        pytest.skip("profile omitted from CTF_OS_LIVE_PROFILES")
    spec = _podman_sandbox_spec(tmp_path, category)
    run_argv = build_run_argv(spec)
    started = subprocess.run(
        run_argv,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert started.returncode == 0, started.stdout + started.stderr
    try:
        result = subprocess.run(
            [
                *user_exec_prefix({"name": spec.name}, workdir="/work"),
                "podman",
                "info",
                "--format",
                "json",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        info = json.loads(result.stdout)
        assert info["host"]["security"]["rootless"] is True
    finally:
        cleaned = cleanup({"name": spec.name, "labels": spec.labels})
        assert cleaned["host_ownership_normalized"] is True
        assert cleaned["removed"] is True


def test_remote_session_requires_exact_declared_identity(repo: Path) -> None:
    _manifest, challenge, run, _race = make_race(repo, category="web")
    metadata = fake_sandbox(run, challenge, "root")
    metadata["target_identities"] = ["nc ctf.example 31337"]
    with pytest.raises(SessionError, match="not declared"):
        open_session(
            metadata, session_id="remote-one", kind="remote", command=["nc", "ctf.example", "31337"],
            target_identity="nc other.example 31337",
        )
