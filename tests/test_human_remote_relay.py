from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from conftest import fake_sandbox, make_race
from test_blackboard_race import _receipt
from test_race_bootstrap import _spec

import ctf_os.agent_tools.__main__ as cli
from ctf_os.blackboard import append_verified_event
from ctf_os.race import (
    attach_lane_sandbox,
    note_command_receipt,
    reserve_lanes,
    status,
)
from ctf_os.sandbox.network import ResolvedTarget, Target
from ctf_os.sandbox.runtime import SandboxError, SandboxSpec, build_run_argv


def _sandbox_spec(
    tmp_path: Path,
    *,
    targets: tuple[ResolvedTarget, ...] = (),
    remote_execution: str = "human-relay",
) -> SandboxSpec:
    source = tmp_path / "input"
    source.mkdir()
    source.chmod(0o555)
    lane_root = tmp_path / "workers" / "root"
    for name in ("work", "evidence", "artifacts", "context"):
        (lane_root / name).mkdir(parents=True, exist_ok=True)
    return SandboxSpec(
        run_id="run-human-relay",
        contest_slug="demo",
        challenge_id="challenge1",
        category="pwn",
        lane_id="root",
        source=source,
        lane_root=lane_root,
        input_fingerprint="0" * 64,
        image="ctf-os-sandbox:pwn",
        targets=targets,
        remote_execution=remote_execution,
    )


def test_human_relay_omits_declared_targets_without_resolving_them() -> None:
    targets = cli._agent_targets(
        ("nc definitely-does-not-resolve.invalid 31337",),
        service_network=None,
        remote_execution="human-relay",
        # A docker binary that cannot exist: if human-relay ever stopped
        # short-circuiting and tried to resolve, invoking it would raise.
        docker="/nonexistent/docker-must-not-run",
    )
    assert targets == ()


def test_human_relay_sandbox_has_no_organizer_network(tmp_path: Path) -> None:
    spec = _sandbox_spec(tmp_path)
    argv = build_run_argv(spec)
    assert argv[argv.index("--network") + 1] == "none"
    assert "org.ctf-os.remote-execution=human-relay" in argv
    assert "CTF_OS_ALLOWED_ENDPOINTS_JSON=[]" in argv


def test_human_relay_may_still_use_a_root_owned_local_service(
    tmp_path: Path,
) -> None:
    spec = replace(
        _sandbox_spec(tmp_path),
        service_network="ctf-os-net-run-human-relay-root",
        service_endpoints=("http://challenge:8080",),
    )
    argv = build_run_argv(spec)
    assert argv[argv.index("--network") + 1] == spec.service_network
    assert "CTF_OS_ALLOWED_ENDPOINTS_JSON=[]" in argv
    assert 'CTF_OS_LOCAL_ENDPOINTS_JSON=["http://challenge:8080"]' in argv


def test_human_relay_rejects_an_authorized_organizer_target(tmp_path: Path) -> None:
    target = ResolvedTarget(
        Target("nc ctf.example 31337", "ctf.example", 31337, "nc"),
        "203.0.113.10",
    )
    with pytest.raises(SandboxError, match="cannot authorize organizer remote"):
        build_run_argv(_sandbox_spec(tmp_path, targets=(target,)))


def test_human_relay_packet_keeps_target_but_requires_participant_execution(
    repo: Path,
) -> None:
    _manifest, challenge, run, race = make_race(
        repo,
        remote="nc ctf.example 31337",
        remote_execution="human-relay",
    )
    note_command_receipt(
        run,
        _receipt(
            run,
            challenge,
            "root",
            "local analysis completed",
            receipt_id="human-relay-root",
        ),
    )
    lane = reserve_lanes(run, [_spec("manual-remote-probe")])[0]
    sandbox = fake_sandbox(run, challenge, lane["lane_id"])
    sandbox["remote_execution"] = "human-relay"
    packet = attach_lane_sandbox(
        run,
        lane_id=str(lane["lane_id"]),
        sandbox=sandbox,
    )

    context = packet["challenge_context"]
    message = packet["spawn_agent_args"]["message"]
    assert race["remote_execution"] == "human-relay"
    assert context["declared_targets"][0]["host"] == "ctf.example"
    assert context["human_remote_relay"]["action_marker"] == "HUMAN_REMOTE_ACTION"
    assert "never send one through any agent tool" in message
    assert "HUMAN_REMOTE_RESULT" in message


@pytest.mark.parametrize(
    ("remote_execution", "expected"),
    (("agent", True), ("human-relay", False)),
)
def test_human_relay_does_not_stagnate_for_missing_organizer_remote_attempt(
    repo: Path,
    remote_execution: str,
    expected: bool,
) -> None:
    _manifest, challenge, run, _race = make_race(
        repo,
        remote="nc ctf.example 31337",
        remote_execution=remote_execution,
    )
    receipt = _receipt(
        run,
        challenge,
        "root",
        "working exploit ready for remote",
        receipt_id=f"primitive-{remote_execution}",
    )
    append_verified_event(
        run,
        event_type="PRIMITIVE",
        lane_id="root",
        attack_family="root-primary",
        receipt=receipt,
    )
    report = status(run, now=datetime.now(UTC) + timedelta(seconds=90))
    signals = report["lanes"][0]["stagnation_signals"]
    assert ("remote-ready-without-remote-attempt" in signals) is expected
    assert report["remote_execution"] == remote_execution
    assert report["metrics"]["remote_execution"] == remote_execution
