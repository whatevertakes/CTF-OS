from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from conftest import fake_sandbox, make_race
from test_blackboard_race import _receipt
from test_race_bootstrap import _spec

import ctf_os.agent_tools.__main__ as cli
from ctf_os.blackboard import (
    append_verified_event,
    register_artifact_inbox,
    shared_artifacts,
)
from ctf_os.race import (
    RaceError,
    attach_lane_sandbox,
    load_race,
    mark_lane_prepare_failed,
    note_command_receipt,
    reserve_lanes,
    status,
)
from ctf_os.sandbox.resources import ResourceError, admission_status, admit
from ctf_os.sandbox.runtime import SandboxSpec, build_run_argv
from ctf_os.service import ServiceSpec
from ctf_os.workspace import atomic_json


def _record_root_attack(run: Path, challenge) -> None:
    note_command_receipt(
        run,
        _receipt(
            run,
            challenge,
            "root",
            "root attack",
            receipt_id="root-operational-attack",
        ),
    )


def test_actual_root_profile_and_early_strong_children_are_recorded(repo: Path) -> None:
    _manifest, challenge, run, race = make_race(
        repo,
        root_model_profile="sol-ultra",
        root_model_profile_source="explicit-cli",
    )
    assert race["lanes"][0]["model_profile"] == "sol-ultra"
    assert race["lanes"][0]["model_profile_source"] == "explicit-cli"
    _record_root_attack(run, challenge)
    lanes = reserve_lanes(
        run,
        [
            _spec("ultra-mechanism", "sol-ultra"),
            _spec("max-mechanism", "sol-max"),
        ],
    )
    packets = []
    for lane in lanes:
        packets.append(
            attach_lane_sandbox(
                run,
                lane_id=lane["lane_id"],
                sandbox=fake_sandbox(run, challenge, lane["lane_id"]),
            )
        )
    ultra = packets[0]["spawn_agent_args"]
    assert ultra["model"] == "gpt-5.6-sol"
    assert ultra["reasoning_effort"] == "ultra"
    assert ultra["fork_turns"] == "none"
    assert packets[1]["spawn_agent_args"]["agent_type"] == "ctf_sol_max"
    report = status(run)
    assert report["metrics"]["root_model_profile"] == "sol-ultra"
    assert report["metrics"]["root_model_profile_source"] == "explicit-cli"
    assert report["metrics"]["model_portfolio"]["lane-1"] == "sol-ultra"


def test_root_sol_max_is_not_subject_to_child_endgame_lease(repo: Path) -> None:
    _manifest, challenge, run, _race = make_race(
        repo,
        root_model_profile="sol-max",
        root_model_profile_source="explicit-cli",
    )
    for index in range(2):
        note_command_receipt(
            run,
            _receipt(
                run,
                challenge,
                "root",
                f"root max attack {index}",
                receipt_id=f"root-max-{index}",
            ),
        )
    later = datetime.now(UTC) + timedelta(minutes=20)
    root = status(run, now=later)["lanes"][0]
    assert root["status"] != "CANCEL_REQUIRED"
    assert "sol-max-lease-exhausted" not in root["stagnation_signals"]


def test_verified_artifact_is_snapshotted_and_visible_in_every_lane_inbox(
    repo: Path,
) -> None:
    _manifest, challenge, run, _race = make_race(repo)
    root_inbox = register_artifact_inbox(run, "root")
    child_inbox = register_artifact_inbox(run, "lane-1")
    artifact = run / "workers" / "root" / "artifacts" / "partial.py"
    artifact.write_bytes(b"print('verified partial')\n")
    event = append_verified_event(
        run,
        event_type="WORKING_POC",
        lane_id="root",
        attack_family="root-primary",
        receipt=_receipt(
            run,
            challenge,
            "root",
            "partial exploit reached controlled state",
            receipt_id="artifact-exchange",
        ),
        artifact="partial.py",
    )
    relative = Path(str(event["shared_artifact_path"]))
    root_copy = root_inbox / relative
    child_copy = child_inbox / relative
    assert root_copy.read_bytes() == artifact.read_bytes()
    assert child_copy.read_bytes() == artifact.read_bytes()
    assert root_copy.stat().st_ino == child_copy.stat().st_ino
    assert not root_copy.stat().st_mode & 0o222
    manifest = shared_artifacts(run)[0]
    assert manifest["container_path"] == f"/shared-artifacts/{relative.as_posix()}"
    assert manifest["artifact_hash"] == hashlib.sha256(artifact.read_bytes()).hexdigest()
    artifact.write_bytes(b"print('mutated later')\n")
    assert root_copy.read_bytes() == b"print('verified partial')\n"

    late_inbox = register_artifact_inbox(run, "lane-2")
    assert (late_inbox / relative).read_bytes() == b"print('verified partial')\n"


def test_admission_reserves_sum_of_running_sandboxes_and_services() -> None:
    records = [
        {
            "Config": {"Labels": {
                "org.ctf-os.managed": "true",
                "org.ctf-os.kind": "sandbox",
            }},
            "State": {"Running": True},
            "HostConfig": {"Memory": 2 * 1024**3, "NanoCpus": 1_000_000_000},
        },
        {
            "Config": {"Labels": {
                "org.ctf-os.managed": "true",
                "org.ctf-os.kind": "service",
            }},
            "State": {"Running": True},
            "HostConfig": {"Memory": 2 * 1024**3, "NanoCpus": 1_000_000_000},
        },
    ]

    def runner(argv, **kwargs):
        if argv[1] == "info":
            return subprocess.CompletedProcess(
                argv, 0,
                json.dumps({"MemTotal": 8 * 1024**3, "NCPU": 4}),
                "",
            )
        if argv[1] == "ps":
            return subprocess.CompletedProcess(argv, 0, "sandbox-id\nservice-id\n", "")
        if argv[1] == "inspect":
            return subprocess.CompletedProcess(argv, 0, json.dumps(records), "")
        raise AssertionError(argv)

    capacity = admission_status(runner=runner)
    assert capacity["reserved_memory_bytes"] == 4 * 1024**3
    assert capacity["reserved_cpus"] == 2
    assert capacity["active_services"] == 1
    admitted = admit("light", race_lane_count=2, runner=runner)
    assert admitted["projected_cpus"] == 3
    with pytest.raises(ResourceError, match="aggregate managed-container"):
        admit("standard", race_lane_count=2, runner=runner)


def test_shared_artifact_inbox_is_mounted_read_only(tmp_path: Path) -> None:
    source = tmp_path / "input"
    source.mkdir()
    source.chmod(0o555)
    lane_root = tmp_path / "workers" / "root"
    for name in ("work", "evidence", "artifacts", "context"):
        (lane_root / name).mkdir(parents=True, exist_ok=True)
    inbox = tmp_path / "exchange" / "inbox" / "root"
    inbox.mkdir(parents=True)
    argv = build_run_argv(SandboxSpec(
        run_id="run-artifact-mount",
        contest_slug="demo",
        challenge_id="challenge1",
        category="web",
        lane_id="root",
        source=source,
        lane_root=lane_root,
        input_fingerprint="0" * 64,
        image="ctf-os-sandbox:web",
        artifact_inbox=inbox,
    ))
    mount = f"type=bind,src={inbox.resolve()},dst=/shared-artifacts,readonly"
    assert mount in argv
    assert "CTF_OS_SHARED_ARTIFACTS=/shared-artifacts" in argv


def test_live_command_heartbeat_suppresses_false_stagnation(repo: Path) -> None:
    _manifest, challenge, run, _race = make_race(repo, category="rev")
    _record_root_attack(run, challenge)
    lane = reserve_lanes(run, [_spec("headless-decompile")])[0]
    sandbox = fake_sandbox(run, challenge, lane["lane_id"], "ctf-os-sandbox:rev")
    attach_lane_sandbox(run, lane_id=lane["lane_id"], sandbox=sandbox)
    running = run / "workers" / lane["lane_id"] / "logs" / "running"
    running.mkdir()
    now = datetime.now(UTC)
    atomic_json(running / "active.json", {
        "schema_version": 1,
        "receipt_id": "active",
        "run_id": run.name,
        "lane_id": lane["lane_id"],
        "argv": ["ctf-ghidra-headless", "/challenge/chall", "1200"],
        "argv_family": "ctf-ghidra-headless:path:arg",
        "target_identity": f"challenge:{challenge.id}",
        "started_at": (now - timedelta(minutes=10)).isoformat(),
        "heartbeat_at": now.isoformat(),
        "last_output_at": None,
        "observed_bytes": 0,
        "status": "RUNNING",
    })
    report = status(run, now=now)
    row = next(value for value in report["lanes"] if value["lane_id"] == lane["lane_id"])
    assert row["in_flight"] is True
    assert row["stagnation_signals"] == []
    assert row["status"] == "PREPARED"


def test_service_instances_share_image_but_not_network_or_runtime_paths(
    tmp_path: Path,
) -> None:
    common = {
        "run_id": "run-service-isolation",
        "challenge_id": "challenge1",
        "source": tmp_path / "input",
        "run_root": tmp_path / "run",
        "plan": {"kind": "dockerfile"},
    }
    root = ServiceSpec(**common, instance_id="root")
    lane = ServiceSpec(**common, instance_id="lane-1")
    assert root.image == lane.image
    assert root.network != lane.network
    assert root.container != lane.container
    assert root.metadata_path != lane.metadata_path
    assert lane.metadata_path == (
        tmp_path / "run" / "service" / "instances" / "lane-1" / "service.json"
    )


def test_bootstrap_prepares_distinct_local_service_instance_for_each_lane(
    repo: Path, monkeypatch
) -> None:
    _manifest, challenge, run, _race = make_race(repo)
    _record_root_attack(run, challenge)
    state = load_race(run)
    state["service_network"] = "ctf-os-net-root-instance"
    state["service_endpoints"] = ["tcp://challenge:31337"]
    state["service_status"] = "READY"
    state["service_isolation"] = "per-lane"
    state["service_instances"] = {
        "root": {
            "status": "READY",
            "instance_id": "root",
            "network": state["service_network"],
            "endpoints": state["service_endpoints"],
        }
    }
    atomic_json(run / "RACE.json", state)
    prepared_instances: list[str] = []
    sandbox_networks: list[str] = []

    def fake_prepare(spec, *, actor, docker="docker"):
        prepared_instances.append(spec.instance_id)
        metadata = (
            run / "service" / "instances" / spec.instance_id / "service.json"
        )
        return {
            "schema_version": 1,
            "status": "READY",
            "run_id": run.name,
            "challenge_id": challenge.id,
            "instance_id": spec.instance_id,
            "network": f"ctf-os-net-private-{spec.instance_id}",
            "endpoints": ["tcp://challenge:31337"],
            "metadata_path": str(metadata),
        }

    def fake_create(spec, docker="docker"):
        sandbox_networks.append(str(spec.service_network))
        value = fake_sandbox(run, challenge, spec.lane_id, spec.image)
        value["service_network"] = spec.service_network
        value["service_endpoints"] = list(spec.service_endpoints)
        return value

    monkeypatch.setattr(cli, "prepare_service", fake_prepare)
    monkeypatch.setattr(cli, "create", fake_create)
    monkeypatch.setattr(
        cli,
        "probe_service_connectivity",
        lambda metadata, docker="docker": {"connected": True},
    )
    result = cli._race_bootstrap(
        repo,
        argparse.Namespace(
            selector="1",
            contest="Demo CTF",
            lanes_json=json.dumps([
                _spec("private-state-one"),
                _spec("private-state-two"),
            ]),
            lanes_file=None,
            docker="docker",
        ),
    )
    assert result["failures"] == []
    assert prepared_instances == ["lane-1", "lane-2"]
    assert sandbox_networks == [
        "ctf-os-net-private-lane-1",
        "ctf-os-net-private-lane-2",
    ]
    instances = load_race(run)["service_instances"]
    assert instances["lane-1"]["network"] != instances["lane-2"]["network"]


def test_batch_reconcile_replaces_per_lane_confirmation_round_trips(
    repo: Path, monkeypatch
) -> None:
    _manifest, challenge, run, _race = make_race(repo)
    _record_root_attack(run, challenge)
    lanes = reserve_lanes(run, [_spec("one-family"), _spec("two-family")])
    for lane in lanes:
        attach_lane_sandbox(
            run,
            lane_id=lane["lane_id"],
            sandbox=fake_sandbox(run, challenge, lane["lane_id"]),
        )
    result = cli._race_reconcile(
        repo,
        argparse.Namespace(
            run_id=run.name,
            docker="docker",
            events_json=json.dumps([
                {
                    "action": "SPAWNED",
                    "lane_id": lanes[0]["lane_id"],
                    "native_session": "thread-one",
                },
                {
                    "action": "SPAWNED",
                    "lane_id": lanes[1]["lane_id"],
                    "native_session": "thread-two",
                },
            ]),
        ),
    )
    assert result["failures"] == []
    assert len(result["results"]) == 2
    state = load_race(run)
    assert [row["status"] for row in state["lanes"][1:]] == ["RUNNING", "RUNNING"]

    monkeypatch.setattr(
        cli,
        "cleanup",
        lambda metadata, docker="docker": {
            "container": metadata["name"],
            "removed": True,
            "already_absent": False,
        },
    )
    stopped = cli._race_reconcile(
        repo,
        argparse.Namespace(
            run_id=run.name,
            docker="docker",
            events_json=json.dumps([{
                "action": "INTERRUPTED",
                "lane_id": lanes[0]["lane_id"],
                "native_session": "thread-one",
            }]),
        ),
    )
    assert stopped["failures"] == []
    assert load_race(run)["lanes"][1]["status"] == "STOPPED"


def test_unspawned_cleanup_failure_blocks_slot_until_controller_retry(
    repo: Path, monkeypatch
) -> None:
    _manifest, challenge, run, _race = make_race(repo)
    _record_root_attack(run, challenge)
    lanes = reserve_lanes(
        run,
        [_spec("cleanup-one"), _spec("cleanup-two"), _spec("cleanup-three")],
    )
    failed = lanes[0]
    attach_lane_sandbox(
        run,
        lane_id=failed["lane_id"],
        sandbox=fake_sandbox(run, challenge, failed["lane_id"]),
    )
    mark_lane_prepare_failed(
        run,
        lane_id=failed["lane_id"],
        reason="probe failed; sandbox cleanup: daemon unavailable",
        cleanup_failed=True,
    )
    with pytest.raises(RaceError, match="concurrency four"):
        reserve_lanes(run, [_spec("replacement-too-early")])

    monkeypatch.setattr(
        cli,
        "cleanup",
        lambda metadata, docker="docker": {
            "container": metadata["name"],
            "removed": True,
            "already_absent": False,
        },
    )
    result = cli.dispatch(
        argparse.Namespace(
            command="race-lane-cleanup",
            run_id=run.name,
            lane=failed["lane_id"],
            docker="docker",
        ),
        repo,
    )
    assert result["lane"]["status"] == "STOPPED"
    assert reserve_lanes(run, [_spec("replacement-after-retry")])
