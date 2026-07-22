from __future__ import annotations

import json
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

import ctf_os.agent_tools.__main__ as agent_tools
from ctf_os.agent_tools.__main__ import build_parser


def test_service_manual_attachment_option_is_visible_and_defaults_to_auto_attach() -> None:
    parser = build_parser()
    help_text = parser._subparsers._group_actions[0].choices["sandbox-create"].format_help()

    assert "--service" in help_text
    assert "active services attach automatically" in help_text
    args = parser.parse_args(["sandbox-create", "1", "--branch", "worker-001"])
    assert args.service is False
    assert args.session_role == "child"


def test_service_read_apis_and_restart_are_exposed() -> None:
    parser = build_parser()
    commands = parser._subparsers._group_actions[0].choices

    assert {"service-status", "service-logs", "service-inspect", "service-restart"}.issubset(commands)


def test_child_tool_surface_omits_shared_lifecycle_and_final_judgment(monkeypatch) -> None:
    monkeypatch.setenv("CTF_OS_SESSION_ROLE", "child")
    commands = build_parser()._subparsers._group_actions[0].choices

    assert {"service-status", "service-logs", "service-inspect", "attack-event"}.issubset(commands)
    assert {
        "branch-service-start", "branch-service-restart", "branch-service-reset", "branch-service-stop",
        "attack-events-show",
        "oast-create", "oast-poll", "oast-events",
    }.issubset(commands)
    assert not {
        "service-build", "service-start", "service-restart", "service-stop", "service-cleanup",
        "sandbox-create", "sandbox-gc", "record-finding", "replay",
        "worker-status", "worker-spawn-packet", "worker-spawn-confirm", "worker-spawn-failed", "worker-replace",
        "worker-endgame", "worker-stop-confirm", "flag-found", "submission-result",
    }.intersection(commands)


def test_child_environment_identity_cannot_be_overridden(monkeypatch) -> None:
    monkeypatch.setenv("CTF_OS_SESSION_ROLE", "child")
    monkeypatch.setenv("CTF_OS_SESSION_ID", "worker-001")
    monkeypatch.setenv("CTF_OS_PARENT_SESSION_ID", "sol-main")
    args = build_parser().parse_args([
        "sandbox-cleanup", "sandbox.json", "--session-id", "worker-002",
    ])

    with pytest.raises(ValueError, match="DENIED_SESSION_IDENTITY"):
        agent_tools._caller(args)


def test_worker_result_controller_commands_are_exposed() -> None:
    parser = build_parser()
    commands = parser._subparsers._group_actions[0].choices

    assert "worker-result-save" not in commands
    assert "worker-results-merge" not in commands


def test_first_to_flag_cli_surface_is_exposed_without_native_launcher() -> None:
    parser = build_parser()
    commands = parser._subparsers._group_actions[0].choices
    assert {
        "worker-status", "worker-spawn-packet", "worker-spawn-confirm", "worker-spawn-failed",
        "worker-replace", "worker-endgame", "worker-stop-confirm", "attack-event", "attack-events-show",
        "flag-found", "submission-result", "oast-create", "oast-poll", "oast-events",
        "branch-service-restart", "branch-service-reset",
    }.issubset(commands)
    assert not {
        "race-plan-start", "branch-admit", "milestone-save", "working-poc-commit",
        "control-action-apply", "benchmark-start",
    }.intersection(commands)
    packet = parser.parse_args([
        "worker-spawn-packet", "1", "--model-profile", "terra-high",
        "--role", "builder", "--context-mode", "directed", "--task", "build exploit",
    ])
    assert packet.model_profile == "terra-high" and packet.role == "builder"
    exec_args = parser.parse_args(["sandbox-exec", "--timeout-profile", "fuzz_slice", "sandbox.json", "--", "true"])
    assert exec_args.timeout == 300 and exec_args.timeout_profile == "fuzz_slice"


def _dispatch_fixture(tmp_path: Path, monkeypatch):
    challenge = SimpleNamespace(
        id="abc123", category="web", workspace_name="jelly-box", key="web/Jelly Box", remotes=(),
    )
    manifest = SimpleNamespace(slug="demo")
    solve_root = tmp_path / "output" / "demo" / "web" / "jelly-box"
    input_path = solve_root / "input"
    input_path.mkdir(parents=True)
    (input_path / "app.py").write_text("print('ok')\n")
    (solve_root / "STATE.json").write_text(json.dumps({
        "schema_version": 1, "challenge_id": "abc123", "status": "PREPARED",
        "branches": [], "flag_candidate": None, "verification": {},
        "input_fingerprint": "source-fp", "updated_at": "2026-07-13T00:00:00Z",
    }))
    plan = {
        "kind": "dockerfile", "services": [{"name": "web", "port": 3000, "internal_target": "http://web:3000"}],
    }
    record = {
        "status": "READY", "prepared_input": str(input_path.resolve()),
        "prepared_fingerprint": "prepared-fp", "source_fingerprint": "source-fp",
        "files": [{"path": "app.py", "size": (input_path / "app.py").stat().st_size}],
        "important_metadata": {"total_bytes": (input_path / "app.py").stat().st_size},
        "authorized_targets": [],
        "service_plan": plan, "recommended_image": "ctf-os-sandbox:web",
        "recommended_resource_profile": "light",
    }
    monkeypatch.setattr(agent_tools, "_load_challenge_strict", lambda *args: (manifest, challenge, record))
    monkeypatch.setattr(agent_tools, "prepared_tree_fingerprint", lambda path: "prepared-fp")
    monkeypatch.setattr(agent_tools, "service_attachment", lambda *args, **kwargs: nullcontext())
    monkeypatch.setattr(agent_tools, "service_inspect", lambda *args, **kwargs: {
        "ownership": {"owner_session_id": "sol-main", "state": "RUNNING"},
        "containers": [{"name": "svc", "state": "running"}],
        "network": {"exists": True, "owned": True, "internal": True},
        "metadata": {"service_endpoints": [{
            "alias": "challenge-service", "protocol": "http", "port": 3000,
            "target": "http://challenge-service:3000",
        }]},
    })
    return solve_root


def test_active_service_is_automatically_attached_with_context_and_probe(tmp_path: Path, monkeypatch) -> None:
    solve_root = _dispatch_fixture(tmp_path, monkeypatch)
    captured = {}

    def fake_create(spec):
        captured["spec"] = spec
        spec.branch_root.mkdir(parents=True, exist_ok=True)
        return {
            "name": "ctf-os-worker", "branch": spec.branch, "branch_root": str(spec.branch_root),
            "metadata_path": str(spec.branch_root / "sandbox.json"), "labels": spec.labels,
            "session_id": spec.session_id, "parent_session_id": spec.parent_session_id,
        }

    monkeypatch.setattr(agent_tools, "create", fake_create)
    monkeypatch.setattr(agent_tools, "probe_service_connectivity", lambda metadata: {"connected": True})
    args = build_parser().parse_args(["--repo", str(tmp_path), "sandbox-create", "1", "--branch", "worker-001"])

    result = agent_tools.dispatch(tmp_path, args)

    spec = captured["spec"]
    assert spec.service_network.startswith("ctf-os-net-")
    assert spec.local_endpoints == ("http://challenge-service:3000",)
    assert spec.service_context["attach_only"] is True
    assert result["connectivity_probe"] == {"connected": True}
    assert Path(result["metadata_path"]).is_file()


def test_attachment_probe_failure_cleans_worker_without_starting_service(tmp_path: Path, monkeypatch) -> None:
    _dispatch_fixture(tmp_path, monkeypatch)
    cleaned = []

    def fake_create(spec):
        spec.branch_root.mkdir(parents=True, exist_ok=True)
        return {
            "name": "ctf-os-worker", "branch": spec.branch, "branch_root": str(spec.branch_root),
            "metadata_path": str(spec.branch_root / "sandbox.json"), "labels": spec.labels,
        }

    monkeypatch.setattr(agent_tools, "create", fake_create)
    monkeypatch.setattr(agent_tools, "probe_service_connectivity", lambda metadata: (_ for _ in ()).throw(RuntimeError("probe failed")))
    monkeypatch.setattr(agent_tools, "cleanup", lambda metadata, **kwargs: cleaned.append(metadata["name"]))
    args = build_parser().parse_args(["--repo", str(tmp_path), "sandbox-create", "1", "--branch", "worker-001"])

    with pytest.raises(RuntimeError, match="probe failed"):
        agent_tools.dispatch(tmp_path, args)

    assert cleaned == ["ctf-os-worker"]


def test_broken_active_service_fails_without_creating_duplicate(tmp_path: Path, monkeypatch) -> None:
    _dispatch_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(agent_tools, "service_inspect", lambda *args, **kwargs: {
        "ownership": {"owner_session_id": "sol-main", "state": "RUNNING"},
        "containers": [],
        "network": {"exists": False, "owned": False, "internal": False},
        "metadata": {},
    })
    monkeypatch.setattr(agent_tools, "create", lambda spec: pytest.fail("sandbox must not be created"))
    args = build_parser().parse_args(["--repo", str(tmp_path), "sandbox-create", "1", "--branch", "worker-001"])

    with pytest.raises(ValueError, match="service container missing, network missing"):
        agent_tools.dispatch(tmp_path, args)
