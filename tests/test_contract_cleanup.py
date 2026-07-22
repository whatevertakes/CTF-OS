from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
import subprocess
import time

import pytest

from ctf_os.agent_tools.__main__ import build_parser
from ctf_os.handoff import save_handoff
from ctf_os.preflight import input_fingerprint
from ctf_os.race import terminate
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


def test_terminal_race_still_owns_resources_until_exact_cleanup(repo: Path) -> None:
    manifest, challenge, run, _race = make_race(repo)
    terminate(run, reason="STOPPED")
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
                "sh", "-c", "test -r /challenge/input.txt && test ! -w /challenge/input.txt",
            ],
            capture_output=True, text=True, timeout=60, check=False,
        )
        assert executed.returncode == 0, executed.stdout + executed.stderr
        assert json.loads(executed.stdout)["result"]["receipt"]["exit_code"] == 0
        opened = subprocess.run(
            [*base, "session-open", "--metadata", metadata, "--session", "shell-one", "--kind", "shell"],
            capture_output=True, text=True, timeout=30, check=False,
        )
        assert opened.returncode == 0, opened.stdout + opened.stderr
        sent = subprocess.run(
            [*base, "session-send", "--metadata", metadata, "--session", "shell-one", "--data", "printf 'SESSION_OK\\n'\n"],
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
            if "SESSION_OK" in session_output:
                break
            time.sleep(0.05)
        assert "SESSION_OK" in session_output
        closed = subprocess.run(
            [*base, "session-close", "--metadata", metadata, "--session", "shell-one"],
            capture_output=True, text=True, timeout=30, check=False,
        )
        assert closed.returncode == 0, closed.stdout + closed.stderr
    finally:
        subprocess.run([*base, "race-end", "--run-id", run_id, "--reason", "STOPPED"], capture_output=True, text=True, timeout=30, check=False)
        cleaned = subprocess.run([*base, "race-cleanup", "--run-id", run_id], capture_output=True, text=True, timeout=60, check=False)
    assert cleaned.returncode == 0, cleaned.stdout + cleaned.stderr
    assert json.loads(cleaned.stdout)["result"]["active_cleared"] is True


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
