from __future__ import annotations

import argparse
import json
import hashlib
import os
from pathlib import Path
import subprocess
import time
import tomllib

import pytest

import ctf_os.agent_tools.__main__ as cli
from ctf_os.agent_tools.__main__ import build_parser
from ctf_os.contest import parse_contest, resolve_selector
from ctf_os.handoff import save_handoff
from ctf_os.preflight import input_fingerprint
from ctf_os.race import load_race, terminate
from ctf_os.workspace import WorkspaceError, create_run

from conftest import make_race


DELETED_MODULES = (
    "ctf_os." + "in" + "take", "ctf_os." + "tri" + "age", "ctf_os." + "problems",
    "ctf_os." + "re" + "play", "ctf_os." + "sw" + "arm", "ctf_os." + "attempts",
    "ctf_os." + "solve_launch", "ctf_os." + "tui",
    "ctf_os.resources." + "sched" + "uler", "ctf_os.sandbox." + "preparation",
    "ctf_os." + "flags", "ctf_os." + "claude_" + "handoff",
)
DELETED_COMMANDS = (
    "prepare" + "-challenge", "sandbox" + "-create", "re" + "play", "in" + "take",
    "tri" + "age-prepare", "resource" + "-request", "sched" + "uler-rebalance",
    "worker" + "-spawn-packet", "submission" + "-result",
)


def test_deleted_modules_and_cli_commands_are_absent() -> None:
    choices = build_parser()._subparsers._group_actions[0].choices
    for command in DELETED_COMMANDS:
        assert command not in choices
    for module in DELETED_MODULES:
        relative = Path(*module.split("."))
        assert not relative.with_suffix(".py").exists()


@pytest.mark.parametrize(
    ("command", "result"),
    (
        ("doctor", {"ok": False, "checks": []}),
        ("image-smoke", {"all_available": False, "profiles": []}),
    ),
)
def test_failed_diagnostics_return_nonzero_and_truthful_wrapper(
    repo: Path,
    monkeypatch,
    capsys,
    command: str,
    result: dict,
) -> None:
    monkeypatch.setattr(cli, "dispatch", lambda args, root: result)
    assert cli.main(["--repo", str(repo), command]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload == {"ok": False, "result": result}


@pytest.mark.parametrize(
    ("command", "result"),
    (
        ("doctor", {"ok": True, "checks": []}),
        ("image-smoke", {"all_available": True, "profiles": []}),
    ),
)
def test_successful_diagnostics_return_zero(
    repo: Path,
    monkeypatch,
    capsys,
    command: str,
    result: dict,
) -> None:
    monkeypatch.setattr(cli, "dispatch", lambda args, root: result)
    assert cli.main(["--repo", str(repo), command]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == {"ok": True, "result": result}


def test_python_controller_has_no_native_model_start_stop_or_flag_submission_code() -> None:
    source = Path("ctf_os")
    python = "\n".join(path.read_text(encoding="utf-8") for path in source.rglob("*.py"))
    assert "tools.spawn_agent" not in python
    assert "collaboration.spawn_agent" not in python
    assert "interrupt_agent(" not in python
    assert "submit_flag" not in python
    assert "submit(flag" not in python


def test_manual_handoff_terminates_only_exact_run_and_writes_one_file(repo: Path) -> None:
    _manifest, _challenge, run, _race = make_race(repo)
    terminal = terminate(run, reason="HANDOFF")
    markdown = f"# Handoff\n\nRun: `{run.name}`\n\nExecuted experiments only.\n"
    destination = save_handoff(
        repo, contest="Demo CTF", challenge="web-Example", run_id=run.name, markdown=markdown
    )
    assert terminal["run_id"] == run.name
    assert terminal["status"] == "HANDOFF"
    assert destination.read_text(encoding="utf-8") == markdown
    assert list(destination.parent.glob("HANDOFF.md")) == [destination]


def test_unsafe_handoff_destination_is_rejected_before_termination(
    repo: Path, tmp_path: Path
) -> None:
    _manifest, _challenge, run, _race = make_race(repo)
    outside = tmp_path / "outside"
    outside.mkdir()
    (repo / "rescue").symlink_to(outside, target_is_directory=True)
    markdown_path = tmp_path / "HANDOFF.md"
    markdown_path.write_text(f"# Handoff\n\nRun: `{run.name}`\n", encoding="utf-8")
    with pytest.raises(ValueError, match="rescue root"):
        cli._race_handoff(
            repo,
            argparse.Namespace(run_id=run.name, markdown_file=str(markdown_path)),
        )
    assert load_race(run)["status"] == "ACTIVE"


def test_terminal_race_still_owns_resources_until_exact_cleanup(repo: Path) -> None:
    manifest, challenge, run, _race = make_race(repo)
    terminate(run, reason="STOPPED")
    with pytest.raises(WorkspaceError, match="race-cleanup"):
        create_run(
            repo, manifest, challenge,
            input_fingerprint=input_fingerprint(manifest, challenge),
        )


def test_user_supplied_sandbox_metadata_must_match_attached_race(
    repo: Path, tmp_path: Path
) -> None:
    _manifest, _challenge, run, race = make_race(repo)
    metadata_path = Path(race["lanes"][0]["sandbox"]["metadata_path"])
    assert cli._authorized_metadata(repo, metadata_path)["run_id"] == run.name
    forged = json.loads(metadata_path.read_text(encoding="utf-8"))
    forged["name"] = "unrelated-container"
    metadata_path.write_text(json.dumps(forged), encoding="utf-8")
    with pytest.raises(ValueError, match="does not match the race"):
        cli._authorized_metadata(repo, metadata_path)


def test_race_cleanup_reports_failure_and_keeps_active_run(
    repo: Path, monkeypatch
) -> None:
    manifest, challenge, run, _race = make_race(repo)
    terminate(run, reason="STOPPED")

    def failed_cleanup(metadata, docker="docker"):
        raise RuntimeError("ownership normalization failed")

    monkeypatch.setattr(cli, "cleanup", failed_cleanup)
    with pytest.raises(RuntimeError, match="race cleanup incomplete"):
        cli._race_cleanup(
            repo,
            argparse.Namespace(run_id=run.name, docker="docker"),
        )
    with pytest.raises(WorkspaceError, match="race-cleanup"):
        create_run(
            repo, manifest, challenge,
            input_fingerprint=input_fingerprint(manifest, challenge),
        )


def test_cli_help_and_package_data_smoke() -> None:
    result = subprocess.run(
        ["python", "-m", "ctf_os.agent_tools", "--help"], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0
    assert "race-prepare" in result.stdout and "race-bootstrap" in result.stdout
    assert "sandbox" + "-create" not in result.stdout
    policy = Path("ctf_os/resources/agent-policy.md")
    assert policy.is_file() and "verified" in policy.read_text(encoding="utf-8").casefold()


def test_ctf_solve_skill_matches_authoritative_profile_and_reconcile_contract() -> None:
    policy = Path("ctf_os/resources/agent-policy.md").read_text(encoding="utf-8")
    skill = Path(".codex/skills/ctf-solve/SKILL.md").read_text(encoding="utf-8")
    normalized_skill = " ".join(skill.split())

    assert "Sol Ultra policy default" in policy
    assert "`root_model_profile` and `root_model_profile_source`" in normalized_skill
    assert "policy default is Sol Ultra" in normalized_skill
    assert "current Root session is Sol xhigh" not in normalized_skill
    assert "one `race-reconcile` call" in normalized_skill
    assert "SPAWNED" in normalized_skill and "INTERRUPTED" in normalized_skill
    assert "Sol max is available only through `race-endgame`" not in normalized_skill
    assert "`race-spawn-confirm`" not in normalized_skill
    assert "`race-stop-confirm`" not in normalized_skill


def test_ares_has_noninteractive_first_run_configuration() -> None:
    config = Path("sandbox/config/ares.toml")
    settings = tomllib.loads(config.read_text(encoding="utf-8"))
    assert settings["human_checker_on"] is False
    assert settings["timeout"] == 5
    assert settings["colourscheme"]["success"] == "0,255,0"

    dockerfile = Path("sandbox/Dockerfile.sandbox").read_text(encoding="utf-8")
    entrypoint = Path("sandbox/entrypoint.sh").read_text(encoding="utf-8")
    assert "COPY sandbox/config/ares.toml /opt/ctf-os/ares-config.toml" in dockerfile
    assert 'if [ ! -e "$HOME/Ares/config.toml" ]' in entrypoint
    assert 'install -m 0600 /opt/ctf-os/ares-config.toml "$HOME/Ares/config.toml"' in entrypoint
    assert 'export JAVA_TOOL_OPTIONS="-Duser.home=$HOME"' in entrypoint


def test_sandbox_build_is_credential_isolated_lock_bound_and_atomic() -> None:
    build = Path("sandbox/build-images.sh").read_text(encoding="utf-8")
    dockerfile = Path("sandbox/Dockerfile.sandbox").read_text(encoding="utf-8")

    assert 'BUILD_DOCKER_CONFIG="$(mktemp -d ' in build
    assert 'printf \'%s\\n\' \'{"auths":{}}\' >"$BUILD_DOCKER_CONFIG/config.json"' in build
    assert '--build-arg "CTF_OS_LOCK_SHA256=${lock_sha256}"' in build
    assert 'ctf-os-sandbox-build:${generation}-${profile}' in build
    failure_check = build.index('if (( ${#FAILED[@]} )); then')
    promotion = build.index('echo "Promoting verified image generation:')
    assert failure_check < promotion
    assert 'org.ctf-os.lock-sha256="${CTF_OS_LOCK_SHA256}"' in dockerfile


def test_remote_installer_archives_are_digest_pinned() -> None:
    installers = (
        "sandbox/install/rev.sh",
        "sandbox/install/web.sh",
        "sandbox/install/cloud.sh",
        "sandbox/install/crypto.sh",
        "sandbox/install/forensic.sh",
        "sandbox/install/osint.sh",
    )
    for path in installers:
        source = Path(path).read_text(encoding="utf-8")
        assert (
            "download_sha256" in source
            or "#sha256=${" in source
        ), path


def test_init_contest_creates_fresh_manifest_and_challenge_folder(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            "python", "-m", "ctf_os.agent_tools", "--repo", str(tmp_path),
            "init-contest", "Demo CTF", "--challenge", "web/Example",
        ],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)["result"]
    manifest = Path(payload["manifest_path"])
    assert Path(payload["challenge_path"]).is_dir()
    assert payload["manifest_created"] is True and payload["challenge_added"] is True
    selected = resolve_selector(parse_contest(manifest).challenges, "web/Example")
    assert selected.key == "web/Example"


def test_temp_contest_race_prepare_dry_smoke(tmp_path: Path) -> None:
    (tmp_path / "incoming" / "Smoke" / "misc" / "One").mkdir(parents=True)
    (tmp_path / "output").mkdir()
    (tmp_path / "incoming" / "Smoke" / "contest.md").write_text(
        "# Contest: Smoke\n- flag_pattern: \\ACTF\\{[^}]+\\}\\Z\n\n### misc/One\n- description: smoke\n",
        encoding="utf-8",
    )
    (tmp_path / "incoming" / "Smoke" / "misc" / "One" / "x.txt").write_text("x", encoding="utf-8")
    result = subprocess.run(
        [
            "python", "-m", "ctf_os.agent_tools", "--repo", str(tmp_path),
            "race-prepare", "1", "--contest", "Smoke", "--dry-run",
        ],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)["result"]
    assert payload["dry_run"] is True
    assert payload["attack_ready"] is False


@pytest.mark.live
@pytest.mark.skipif(os.environ.get("CTF_OS_LIVE") != "1", reason="set CTF_OS_LIVE=1")
def test_all_category_images_run_live_smoke() -> None:
    for profile in ("base", "pwn", "web", "rev", "crypto", "forensic", "misc", "osint", "ai", "cloud"):
        result = subprocess.run(
            ["docker", "run", "--rm", "--network", "none", f"ctf-os-sandbox:{profile}", "true"],
            capture_output=True, text=True, timeout=60, check=False,
        )
        assert result.returncode == 0, f"{profile}: {result.stderr}"


@pytest.mark.live
@pytest.mark.skipif(os.environ.get("CTF_OS_LIVE") != "1", reason="set CTF_OS_LIVE=1")
@pytest.mark.parametrize("profile", ("crypto", "misc"))
def test_ares_decodes_on_first_fresh_sandbox_command(profile: str) -> None:
    result = subprocess.run(
        [
            "docker", "run", "--rm", "--read-only", "--network", "none",
            "--cap-drop", "ALL",
            "--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "SETPCAP",
            "--cap-add", "CHOWN", "--cap-add", "DAC_READ_SEARCH",
            "--security-opt", "no-new-privileges",
            "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=256m,mode=1777",
            "--tmpfs", "/work:rw,exec,nosuid,nodev,size=256m,mode=0777",
            "--tmpfs", "/artifacts:rw,nosuid,nodev,size=128m,mode=0777",
            "--tmpfs", "/home/ctf/.cache:rw,nosuid,nodev,size=256m,mode=0700,uid=1001,gid=1001",
            f"ctf-os-sandbox:{profile}",
            "sh", "-ec",
            'test "$(stat -c %a "$HOME/Ares/config.toml")" = 600; '
            "ares -t SGVsbG8sIENURi1PUyE= -d | tee /artifacts/ares-first.out; "
            "grep -q 'Hello, CTF-OS!' /artifacts/ares-first.out",
        ],
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.live
@pytest.mark.skipif(os.environ.get("CTF_OS_LIVE") != "1", reason="set CTF_OS_LIVE=1")
def test_live_temp_contest_prepare_exec_and_exact_cleanup(tmp_path: Path) -> None:
    challenge = tmp_path / "incoming" / "Live" / "base" / "One"
    challenge.mkdir(parents=True)
    (tmp_path / "output").mkdir()
    (challenge.parents[1] / "contest.md").write_text(
        "# Contest: Live\n- flag_pattern: \\ACTF\\{[^}]+\\}\\Z\n\n### base/One\n- description: live smoke\n",
        encoding="utf-8",
    )
    (challenge / "input.txt").write_text("immutable\n", encoding="utf-8")
    base = ["python", "-m", "ctf_os.agent_tools", "--repo", str(tmp_path)]
    prepared = subprocess.run(
        [*base, "race-prepare", "1", "--contest", "Live"],
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert prepared.returncode == 0, prepared.stdout + prepared.stderr
    result = json.loads(prepared.stdout)["result"]
    assert result["attack_ready"] is True
    run_id = result["run_id"]
    metadata = result["root_sandbox"]["metadata_path"]
    try:
        executed = subprocess.run(
            [
                *base, "sandbox-exec", "--metadata", metadata, "--",
                "sh", "-c",
                "test -r /challenge/input.txt && test ! -w /challenge/input.txt && "
                "grep -Eq '^CapEff:[[:space:]]+0+$' /proc/self/status && "
                "test \"$HOME\" = /work/home && "
                "test \"$XDG_CONFIG_HOME\" = /work/home/.config && "
                "test \"$XDG_CACHE_HOME\" = /work/home/.cache && "
                "test \"$XDG_DATA_HOME\" = /work/home/.local/share && "
                "test \"$XDG_RUNTIME_DIR\" = /work/runtime && "
                "test \"$AWS_CONFIG_FILE\" = /work/credentials/aws-config && "
                "test \"$AZURE_CONFIG_DIR\" = /work/credentials/azure && "
                "test \"$CLOUDSDK_CONFIG\" = /work/credentials/gcloud && "
                "test \"$KUBECONFIG\" = /work/credentials/kubeconfig",
            ],
            capture_output=True, text=True, timeout=60, check=False,
        )
        assert executed.returncode == 0, executed.stdout + executed.stderr
        assert json.loads(executed.stdout)["result"]["receipt"]["exit_code"] == 0
        created = subprocess.run(
            [
                *base, "sandbox-exec", "--metadata", metadata, "--",
                "sh", "-c",
                "mkdir -m 700 /work/private && "
                "printf solver > /work/private/solver.py && chmod 600 /work/private/solver.py && "
                "printf artifact > /artifacts/result.bin && chmod 600 /artifacts/result.bin",
            ],
            capture_output=True, text=True, timeout=60, check=False,
        )
        assert created.returncode == 0, created.stdout + created.stderr
        assert json.loads(created.stdout)["result"]["receipt"]["exit_code"] == 0
        opened = subprocess.run(
            [*base, "session-open", "--metadata", metadata, "--session", "shell-one", "--kind", "shell"],
            capture_output=True, text=True, timeout=30, check=False,
        )
        assert opened.returncode == 0, opened.stdout + opened.stderr
        sent = subprocess.run(
            [
                *base, "session-send", "--metadata", metadata,
                "--session", "shell-one", "--data",
                "printf 'SESSION_OK:%s:%s\\n' \"$HOME\" \"$CLOUDSDK_CONFIG\"\n",
            ],
            capture_output=True, text=True, timeout=30, check=False,
        )
        assert sent.returncode == 0, sent.stdout + sent.stderr
        session_output = ""
        for _ in range(10):
            read = subprocess.run(
                [*base, "session-read", "--metadata", metadata, "--session", "shell-one", "--limit", "4096"],
                capture_output=True, text=True, timeout=30, check=False,
            )
            assert read.returncode == 0, read.stdout + read.stderr
            session_output += json.loads(read.stdout)["result"]["receipt"]["observed_output"]
            if "SESSION_OK:/work/home:/work/credentials/gcloud" in session_output:
                break
            time.sleep(0.05)
        assert "SESSION_OK:/work/home:/work/credentials/gcloud" in session_output
        closed = subprocess.run(
            [*base, "session-close", "--metadata", metadata, "--session", "shell-one"],
            capture_output=True, text=True, timeout=30, check=False,
        )
        assert closed.returncode == 0, closed.stdout + closed.stderr
    finally:
        subprocess.run([*base, "race-end", "--run-id", run_id, "--reason", "STOPPED"], capture_output=True, text=True, timeout=30, check=False)
        cleaned = subprocess.run([*base, "race-cleanup", "--run-id", run_id], capture_output=True, text=True, timeout=60, check=False)
    assert cleaned.returncode == 0, cleaned.stdout + cleaned.stderr
    cleanup_result = json.loads(cleaned.stdout)["result"]
    assert cleanup_result["active_cleared"] is True
    assert cleanup_result["cleaned"][0]["host_ownership_normalized"] is True
    lane_root = Path(metadata).parent
    for path in (lane_root / "work" / "private", lane_root / "work" / "private" / "solver.py",
                 lane_root / "artifacts" / "result.bin"):
        assert path.stat().st_uid == os.getuid()
    assert (lane_root / "work" / "private" / "solver.py").read_text() == "solver"
    assert (lane_root / "artifacts" / "result.bin").read_text() == "artifact"


@pytest.mark.live
@pytest.mark.skipif(os.environ.get("CTF_OS_LIVE") != "1", reason="set CTF_OS_LIVE=1")
def test_live_root_owned_service_is_prepared_probed_and_fully_cleaned(tmp_path: Path) -> None:
    challenge = tmp_path / "incoming" / "Live Service" / "web" / "HTTP"
    challenge.mkdir(parents=True)
    (tmp_path / "output").mkdir()
    (challenge.parents[1] / "contest.md").write_text(
        "# Contest: Live Service\n- flag_pattern: \\ACTF\\{[^}]+\\}\\Z\n\n"
        "### web/HTTP\n- description: local service smoke\n",
        encoding="utf-8",
    )
    (challenge / "Dockerfile").write_text(
        "FROM ctf-os-sandbox:base\n"
        "ENTRYPOINT []\n"
        "COPY index.html /srv/index.html\n"
        "EXPOSE 8000\n"
        'CMD ["python3", "-m", "http.server", "8000", "--directory", "/srv"]\n',
        encoding="utf-8",
    )
    (challenge / "index.html").write_text("SERVICE_OK\n", encoding="utf-8")
    base = ["python", "-m", "ctf_os.agent_tools", "--repo", str(tmp_path)]
    run_id: str | None = None
    prepared = subprocess.run(
        [*base, "race-prepare", "1", "--contest", "Live Service"],
        capture_output=True, text=True, timeout=180, check=False,
    )
    assert prepared.returncode == 0, prepared.stdout + prepared.stderr
    result = json.loads(prepared.stdout)["result"]
    run_id = result["run_id"]
    metadata = result["root_sandbox"]["metadata_path"]
    service_image = f"ctf-os-challenge:{hashlib.sha256(run_id.encode()).hexdigest()[:12]}"
    assert result["attack_ready"] is True
    assert result["service"]["status"] == "READY"
    assert result["root_sandbox"]["service_probe"]["connected"] is True
    try:
        executed = subprocess.run(
            [
                *base, "sandbox-exec", "--metadata", metadata,
                "--target", "http://challenge:8000", "--",
                "python3", "-c",
                "import urllib.request; print(urllib.request.urlopen('http://challenge:8000', timeout=5).read().decode())",
            ],
            capture_output=True, text=True, timeout=60, check=False,
        )
        assert executed.returncode == 0, executed.stdout + executed.stderr
        receipt = json.loads(executed.stdout)["result"]["receipt"]
        assert receipt["exit_code"] == 0
        assert "SERVICE_OK" in receipt["observed_output"]
        assert receipt["target_observed"] is True
    finally:
        subprocess.run(
            [*base, "race-end", "--run-id", run_id, "--reason", "STOPPED"],
            capture_output=True, text=True, timeout=30, check=False,
        )
        cleaned = subprocess.run(
            [*base, "race-cleanup", "--run-id", run_id],
            capture_output=True, text=True, timeout=120, check=False,
        )
    assert cleaned.returncode == 0, cleaned.stdout + cleaned.stderr
    cleanup_result = json.loads(cleaned.stdout)["result"]
    assert cleanup_result["active_cleared"] is True
    assert not cleanup_result["failures"]
    image = subprocess.run(
        ["docker", "image", "inspect", service_image], capture_output=True, text=True, check=False
    )
    assert image.returncode != 0


@pytest.mark.live
@pytest.mark.skipif(os.environ.get("CTF_OS_LIVE") != "1", reason="set CTF_OS_LIVE=1")
def test_live_declared_target_firewall_allows_only_exact_ip_and_port(
    tmp_path: Path,
) -> None:
    suffix = hashlib.sha256(str(tmp_path).encode()).hexdigest()[:12]
    allowed_name = f"ctf-os-live-allowed-{suffix}"
    blocked_name = f"ctf-os-live-blocked-{suffix}"
    targets = (allowed_name, blocked_name)
    base = ["python", "-m", "ctf_os.agent_tools", "--repo", str(tmp_path)]
    run_id: str | None = None
    cleaned: subprocess.CompletedProcess[str] | None = None

    try:
        for name in targets:
            started = subprocess.run(
                [
                    "docker", "run", "--detach", "--rm", "--name", name,
                    "--network", "bridge", "ctf-os-sandbox:base",
                    "python3", "-m", "http.server", "8000",
                ],
                capture_output=True, text=True, timeout=60, check=False,
            )
            assert started.returncode == 0, started.stdout + started.stderr

        addresses: dict[str, str] = {}
        for name in targets:
            inspected = subprocess.run(
                [
                    "docker", "inspect", "--format",
                    "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                    name,
                ],
                capture_output=True, text=True, timeout=30, check=False,
            )
            assert inspected.returncode == 0, inspected.stdout + inspected.stderr
            addresses[name] = inspected.stdout.strip()
            assert addresses[name]

        challenge = tmp_path / "incoming" / "Live Remote" / "base" / "Firewall"
        challenge.mkdir(parents=True)
        (tmp_path / "output").mkdir()
        declared = json.dumps(
            {
                "host": addresses[allowed_name],
                "port": 8000,
                "protocol": "http",
                "organizer_declared": True,
            },
            separators=(",", ":"),
        )
        (challenge.parents[1] / "contest.md").write_text(
            "# Contest: Live Remote\n"
            "- flag_pattern: \\ACTF\\{[^}]+\\}\\Z\n\n"
            "### base/Firewall\n"
            "- description: declared-target firewall smoke\n"
            f"- remote: {declared}\n",
            encoding="utf-8",
        )
        (challenge / "input.txt").write_text("firewall\n", encoding="utf-8")

        prepared = subprocess.run(
            [*base, "race-prepare", "1", "--contest", "Live Remote"],
            capture_output=True, text=True, timeout=120, check=False,
        )
        assert prepared.returncode == 0, prepared.stdout + prepared.stderr
        result = json.loads(prepared.stdout)["result"]
        assert result["attack_ready"] is True
        run_id = result["run_id"]
        metadata = result["root_sandbox"]["metadata_path"]
        identity = result["root_sandbox"]["authorized_targets"][0]["declared"]

        allowed = subprocess.run(
            [
                *base, "sandbox-exec", "--metadata", metadata,
                "--target", identity, "--",
                "python3", "-c",
                (
                    "import urllib.request,sys; "
                    "print(urllib.request.urlopen(sys.argv[1],timeout=3).status)"
                ),
                f"http://{addresses[allowed_name]}:8000/",
            ],
            capture_output=True, text=True, timeout=30, check=False,
        )
        assert allowed.returncode == 0, allowed.stdout + allowed.stderr
        allowed_receipt = json.loads(allowed.stdout)["result"]["receipt"]
        assert allowed_receipt["exit_code"] == 0
        assert allowed_receipt["target_observed"] is True
        assert allowed_receipt["target_packets_after"] > allowed_receipt["target_packets_before"]

        blocked = subprocess.run(
            [
                *base, "sandbox-exec", "--metadata", metadata,
                "--target", identity, "--timeout", "5", "--",
                "python3", "-c",
                (
                    "import socket,sys; "
                    "socket.create_connection((sys.argv[1],int(sys.argv[2])),1)"
                ),
                addresses[blocked_name], "8000",
            ],
            capture_output=True, text=True, timeout=30, check=False,
        )
        assert blocked.returncode == 0, blocked.stdout + blocked.stderr
        blocked_receipt = json.loads(blocked.stdout)["result"]["receipt"]
        assert blocked_receipt["exit_code"] != 0
        assert blocked_receipt["target_observed"] is False
        assert (
            blocked_receipt["target_packets_after"]
            == blocked_receipt["target_packets_before"]
        )
    finally:
        if run_id is not None:
            subprocess.run(
                [*base, "race-end", "--run-id", run_id, "--reason", "STOPPED"],
                capture_output=True, text=True, timeout=30, check=False,
            )
            cleaned = subprocess.run(
                [*base, "race-cleanup", "--run-id", run_id],
                capture_output=True, text=True, timeout=60, check=False,
            )
        for name in targets:
            subprocess.run(
                ["docker", "rm", "--force", name],
                capture_output=True, text=True, timeout=30, check=False,
            )

    assert cleaned is not None
    assert cleaned.returncode == 0, cleaned.stdout + cleaned.stderr
    assert json.loads(cleaned.stdout)["result"]["active_cleared"] is True
