from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from dataclasses import replace
from types import SimpleNamespace

import pytest

from ctf_os.agent_tools.__main__ import build_parser
from ctf_os.contest import ChallengeSpec, ContestManifest
from ctf_os.preflight import prepared_tree_fingerprint
from ctf_os.rescue import (
    RescueError,
    _load_packet,
    calculate_packet_digest,
    canonical_json,
    close_rescue,
    load_rescue_ledger,
    prepare_rescue,
    promote_rescue_flag,
    record_rescue_runtime,
    rescue_attempt_id,
    show_rescue,
    validate_exact_live_mutable_run,
    validate_rescue_return,
)
from ctf_os.rescue_backend import RescueBackend
from ctf_os.rescue_hooks import handle_hook
from ctf_os.rescue_mcp import StdioMCPServer
from ctf_os.rescue_sessions import RescueSessionManager
from ctf_os.rescue_tool import (
    _artifact_snapshot, _import_input, _input_files, _record_command_receipt,
    _reject_model_command, _safe_relative, _sandbox_control,
)
from ctf_os.sandbox.network import ResolvedTarget, Target
from ctf_os.sandbox.preparation import (
    PreparedSandbox,
    RESCUE_SERVICE_ERROR,
    prepare_sandbox_spec,
)
from ctf_os.sandbox.runtime import (
    SandboxSpec, build_run_argv, cleanup as cleanup_sandbox,
    create as create_sandbox, execute as execute_sandbox,
)
from ctf_os.workspace import atomic_json


FINGERPRINT = "a" * 64
SNAPSHOT = "b" * 64
COMMIT = "c" * 40
RUN_ID = "run-live-001"


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(value, str):
        path.write_text(value, encoding="utf-8")
    else:
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


@pytest.fixture
def rescue_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    repo = tmp_path / "repo"
    claude_home = tmp_path / "CTF-OS-claude"
    claude_home.mkdir()
    monkeypatch.setenv("CTF_OS_CLAUDE_HOME", str(claude_home))
    contest_path = repo / "incoming" / "demo" / "contest.md"
    _write(contest_path, "# Demo\n")
    challenge = ChallengeSpec(
        number=1,
        id="challenge-001",
        category="pwn",
        name="Rescue Me",
        workspace_name="rescue-me",
        score=500,
        description="authorized test",
        hint=None,
        remotes=("tcp://example.com:31337",),
        flag_format="CTF{...}",
        flag_pattern=r"\ACTF\{[^}]+\}\Z",
        input_profile="standard",
    )
    manifest = ContestManifest(
        name="Demo", slug="demo", path=contest_path, date=None,
        flag_format="CTF{...}", flag_pattern=challenge.flag_pattern,
        input_profile="standard", challenges=(challenge,),
    )
    workspace = repo / "output" / "demo" / "pwn" / "rescue-me"
    input_root = workspace / "input"
    input_root.mkdir(parents=True)
    _write(input_root / "chall", "prepared input\n")
    run = workspace / "runs" / RUN_ID
    run.mkdir(parents=True)
    state = {
        "schema_version": 1,
        "run_id": RUN_ID,
        "attempt_id": "attempt-001",
        "challenge_instance_id": "instance-001",
        "challenge_id": challenge.id,
        "input_fingerprint": FINGERPRINT,
        "fingerprint_scheme": "challenge-local-v2",
        "target_revision": 1,
        "challenge_snapshot_digest": SNAPSHOT,
        "transformation_seed": "NONE",
        "solve_mode": "adaptive-race",
        "status": "SOLVING",
        "competition_state": "ACTIVE",
        "sealed": False,
        "submission_recommended": False,
        "remote_flag_receipt": None,
        "branches": [],
        "planned_child_width": 0,
        "active_child_width": 0,
    }
    run_manifest = {
        "schema_version": 1,
        "run_id": RUN_ID,
        "attempt_id": "attempt-001",
        "challenge_instance_id": "instance-001",
        "arm": "LIVE",
        "stratum": "LIVE_CONTEST",
        "matched_block_id": None,
        "mode": "adaptive-race",
        "challenge_snapshot_digest": SNAPSHOT,
        "identity": {
            "run_id": RUN_ID,
            "attempt_id": "attempt-001",
            "challenge_instance_id": "instance-001",
        },
        "challenge": {
            "challenge_id": challenge.id,
            "input_fingerprint": FINGERPRINT,
            "target_revision": 1,
        },
        "repository": {"commit_sha": COMMIT, "dirty_diff_digest": None},
    }
    record = {
        "status": "READY",
        "blockers": [],
        "prepared_input": str(input_root.resolve()),
        "source_fingerprint": FINGERPRINT,
        "prepared_fingerprint": "prepared-digest",
        "recommended_image": "ctf-os-sandbox:pwn",
        "recommended_resource_profile": "standard",
        "files": [{"path": "chall", "size": 15}],
        "important_metadata": {"total_bytes": 15},
        "authorized_targets": [{
            "host": "example.com", "port": 31337, "protocol": "tcp",
            "organizer_declared": True, "declared": "tcp://example.com:31337",
        }],
        "service_plan": None,
    }
    _write(run / "STATE.json", state)
    _write(run / "RUN_MANIFEST.json", run_manifest)
    _write(run / "SOLVE-LAUNCH.json", {"schema_version": 1, "run_id": RUN_ID})
    _write(run / "candidates.json", {"schema_version": 1, "candidates": []})
    _write(workspace / "target-revisions.jsonl", json.dumps({
        "target_revision": 1, "input_fingerprint": FINGERPRINT,
    }, separators=(",", ":")) + "\n")
    _write(workspace / "CHALLENGE-PREFLIGHT.json", {
        "source_fingerprint": FINGERPRINT,
        "prepared_fingerprint": "prepared-digest",
    })
    return SimpleNamespace(
        repo=repo, claude_home=claude_home, manifest=manifest,
        challenge=challenge, workspace=workspace,
        input_root=input_root, run=run, state=state,
        run_manifest=run_manifest, record=record,
    )


def _fake_preparer(**kwargs: object) -> PreparedSandbox:
    target = Target(
        "tcp://example.com:31337", "example.com", 31337, "tcp",
        organizer_declared=True,
    )
    spec = SandboxSpec(
        contest_slug=str(kwargs["manifest"].slug),
        challenge_id=str(kwargs["challenge"].id),
        branch=str(kwargs["branch"]),
        source=Path(kwargs["workspace"]) / "input",
        branch_root=Path(kwargs["branch_root"]),
        input_fingerprint=FINGERPRINT,
        target_revision=1,
        input_bytes=15,
        targets=(ResolvedTarget(target, "93.184.216.34"),),
        image="ctf-os-sandbox:pwn",
        resource_profile="standard",
        session_id=str(kwargs["session_id"]),
        parent_session_id="sol-main",
        session_role="external-rescue",
        category="pwn",
        workload_class="external-rescue",
        workspace_mode="bind",
        run_id=str(kwargs["run_id"]),
        rescue_attempt_id=str(kwargs["rescue_attempt_id"]),
        external_solver=True,
        solver_family="claude",
        session_kind="external-rescue",
        requested_lead_model=str(kwargs["requested_lead_model"]),
    )
    return PreparedSandbox(spec=spec, attachment_service=None, service_context={})


def _fake_create(spec: SandboxSpec) -> dict[str, object]:
    for name in ("work", "evidence", "artifacts", "logs", "context"):
        (spec.branch_root / name).mkdir(parents=True, exist_ok=True)
    metadata: dict[str, object] = {
        "schema_version": 2,
        "name": spec.name,
        "branch": spec.branch,
        "branch_root": str(spec.branch_root),
        "source": str(spec.source),
        "metadata_path": str(spec.branch_root / "sandbox.json"),
        "labels": spec.labels,
        "runtime_labels": spec.runtime_labels,
        "run_id": spec.run_id,
        "rescue_attempt_id": spec.rescue_attempt_id,
        "session_id": spec.session_id,
        "parent_session_id": spec.parent_session_id,
        "session_role": spec.session_role,
        "external_solver": spec.external_solver,
        "solver_family": spec.solver_family,
        "session_kind": spec.session_kind,
        "requested_lead_model": spec.requested_lead_model,
        "workspace_mode": spec.workspace_mode,
        "input_fingerprint": spec.input_fingerprint,
        "target_revision": spec.target_revision,
        "authorized_targets": [row.to_dict() for row in spec.targets],
        "local_endpoints": [],
        "service_context": {},
        "resource_profile": spec.resource_profile,
        "service_network": None,
    }
    atomic_json(spec.branch_root / "sandbox.json", metadata)
    return metadata


def _prepare(case: SimpleNamespace, **changes: object) -> dict[str, object]:
    values: dict[str, object] = {
        "mode": "PRIMITIVE_TO_POC",
        "profile": "standard",
        "objective": "Turn the current primitive into an executable PoC",
        "current_blocker": "The final protocol framing is not yet verified",
        "operation_id": "rescue-operation-001",
        "leading_exploit_path": "Use the controlled overwrite to redirect execution",
        "sandbox_factory": _fake_create,
        "sandbox_preparer": _fake_preparer,
        "prepared_fingerprint_reader": lambda _path: "prepared-digest",
    }
    values.update(changes)
    return prepare_rescue(
        case.repo, case.manifest, case.challenge, case.record, case.run, **values,
    )


def _rescue_root(case: SimpleNamespace, result: dict[str, object]) -> Path:
    return Path(str(result["path"]))


def test_prepare_without_intake_triage_and_session_input_adapter(rescue_case: SimpleNamespace) -> None:
    rescue_case.record["input_source"] = "session-input"
    result = _prepare(rescue_case)
    root = _rescue_root(rescue_case, result)
    assert root.is_relative_to(rescue_case.claude_home / "runs")
    pointer = (
        rescue_case.run / "rescue" / "RESCUE_POINTERS" /
        f"{result['rescue_attempt_id']}.json"
    )
    assert pointer.is_file()
    assert not (rescue_case.workspace / "INTAKE.md").exists()
    assert not (rescue_case.workspace / "TRIAGE.md").exists()
    assert (root / "RESCUE_PACKET.json").is_file()


def test_cli_requires_exact_run_id() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([
            "rescue-prepare", "1", "--contest", "demo",
            "--mode", "BLOCKER_BREAK", "--objective", "break blocker",
            "--current-blocker", "unknown byte", "--operation-id", "op-1",
        ])


def test_wrong_exact_run_is_rejected(rescue_case: SimpleNamespace) -> None:
    other = rescue_case.run.parent / "wrong-run"
    other.mkdir()
    with pytest.raises(RescueError, match="wrong-run"):
        validate_exact_live_mutable_run(other, rescue_case.challenge, rescue_case.record)


def test_changed_snapshot_and_challenge_instance_are_rejected(
    rescue_case: SimpleNamespace,
) -> None:
    rescue_case.state["challenge_snapshot_digest"] = "d" * 64
    _write(rescue_case.run / "STATE.json", rescue_case.state)
    with pytest.raises(RescueError, match="snapshot"):
        _prepare(rescue_case)
    rescue_case.state["challenge_snapshot_digest"] = SNAPSHOT
    rescue_case.state["challenge_instance_id"] = "wrong-instance"
    _write(rescue_case.run / "STATE.json", rescue_case.state)
    with pytest.raises(RescueError, match="instance identity"):
        _prepare(rescue_case)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda case: case.state.update(input_fingerprint="d" * 64), "stale input fingerprint"),
        (lambda case: case.state.update(target_revision=2), "changed target revision"),
        (lambda case: case.state.update(sealed=True), "sealed run"),
        (lambda case: case.state.update(status="ACCEPTED"), "ACCEPTED"),
        (lambda case: case.state.update(status="SOLVED"), "SOLVED"),
        (lambda case: case.state.update(submission_recommended=True), "submission recommendation"),
    ],
)
def test_live_mutability_rejections(
    rescue_case: SimpleNamespace, mutation: object, message: str,
) -> None:
    mutation(rescue_case)
    _write(rescue_case.run / "STATE.json", rescue_case.state)
    with pytest.raises(RescueError, match=message):
        _prepare(rescue_case)


def test_verified_remote_receipt_rejects_prepare(rescue_case: SimpleNamespace) -> None:
    _write(rescue_case.run / "flag-receipts" / "remote-one.json", {
        "schema_version": 2, "network_observed": True,
    })
    with pytest.raises(RescueError, match="already exists"):
        _prepare(rescue_case)


@pytest.mark.parametrize("arm", ["A", "B", "C", "D"])
def test_benchmark_arms_reject_rescue(rescue_case: SimpleNamespace, arm: str) -> None:
    rescue_case.run_manifest.update({
        "arm": arm, "stratum": "benchmark", "matched_block_id": "block-1",
    })
    _write(rescue_case.run / "RUN_MANIFEST.json", rescue_case.run_manifest)
    with pytest.raises(RescueError, match="LIVE competition"):
        _prepare(rescue_case)


def test_prepare_is_idempotent_and_conflicts_on_changed_material(rescue_case: SimpleNamespace) -> None:
    first = _prepare(rescue_case)
    second = _prepare(rescue_case)
    assert first["rescue_attempt_id"] == second["rescue_attempt_id"]
    assert second["idempotent"] is True
    with pytest.raises(RescueError, match="conflicting canonical rescue material"):
        _prepare(rescue_case, objective="A different exact objective")


def test_packet_identity_digest_tree_and_standard_model(rescue_case: SimpleNamespace) -> None:
    before_state = (rescue_case.run / "STATE.json").read_bytes()
    before_lineage = b""
    result = _prepare(rescue_case)
    root = _rescue_root(rescue_case, result)
    packet = json.loads((root / "RESCUE_PACKET.json").read_text())
    assert packet["identity"] == packet["identity"] | {
        "run_id": RUN_ID,
        "attempt_id": "attempt-001",
        "challenge_instance_id": "instance-001",
        "input_fingerprint": FINGERPRINT,
        "target_revision": 1,
        "repository_commit": COMMIT,
    }
    assert packet["identity"]["contest"] == "demo"
    assert packet["packet_digest"] == calculate_packet_digest(packet)
    assert canonical_json(packet) == canonical_json(json.loads(canonical_json(packet)))
    assert root.stat().st_ino
    expected = {
        "CLAUDE.md", "REQUEST.md", "MODEL_POLICY.md", "START.md",
        "RESCUE_PACKET.json", "RESCUE_STATE.json", "RETURN.schema.json",
        "RETURN.example.json", "RESCUE_COMMANDS.jsonl",
        "CLAUDE_RETURN.json", "CODEX-RESUME.md", "ctf-tool", "sandbox.json",
        ".claude", "context", "work", "evidence", "artifacts", "logs",
    }
    assert expected.issubset({path.name for path in root.iterdir()})
    assert "claude --model sonnet" in result["start_command"]
    assert result["observed_lead_model"] is None
    assert not any((root / ".claude" / "agents").iterdir())
    assert (root / "context" / "rescue-memory.json").is_file()
    assert (root / "ctf-tool").stat().st_mode & 0o222 == 0
    assert (root / "context").stat().st_mode & 0o222 == 0
    assert (root / ".claude").stat().st_mode & 0o222 == 0
    assert (root / "RESCUE_PACKET.json").stat().st_mode & 0o222 == 0
    assert (rescue_case.run / "STATE.json").read_bytes() == before_state
    assert not (rescue_case.run / "RACE_LINEAGE.jsonl").exists()
    assert before_lineage == b""
    resources = json.loads((rescue_case.run / "RESOURCE_STATE.json").read_text())
    request = resources["requests"][str(result["rescue_attempt_id"])]
    assert request["workload_class"] == "external-rescue"
    assert resources["allocations"] == {}


def test_deep_requested_model_is_opus(rescue_case: SimpleNamespace) -> None:
    result = _prepare(
        rescue_case, profile="deep", mode="FRESH_REINTERPRETATION",
        operation_id="deep-op-1",
    )
    root = _rescue_root(rescue_case, result)
    assert "claude --model opus" in result["start_command"]
    assert result["fallback_command"] is None
    assert result["observed_lead_model"] is None
    start = (root / "START.md").read_text()
    assert "--dangerously-skip-permissions" not in start
    assert "Observed model" in start


def test_fable_strategy_is_separate_from_deep(rescue_case: SimpleNamespace) -> None:
    result = _prepare(
        rescue_case, profile="fable-strategy", mode="FRESH_REINTERPRETATION",
        operation_id="fable-strategy-op",
    )
    root = _rescue_root(rescue_case, result)
    assert "claude --model claude-fable-5" in result["start_command"]
    assert "claude --model opus" in result["fallback_command"]
    assert (root / ".claude" / "agents" / "clean-room-recon-haiku.md").is_file()


def test_assisted_requested_model_is_sonnet_and_not_observed(
    rescue_case: SimpleNamespace,
) -> None:
    result = _prepare(
        rescue_case, profile="assisted", operation_id="assisted-model-op",
    )
    assert result["requested_lead_model"] == "sonnet"
    assert result["observed_lead_model"] is None
    root = _rescue_root(rescue_case, result)
    policy = json.loads((root / "RESCUE_PACKET.json").read_text())["model_policy"]
    assert policy["maximum_initial_subagent_invocations"] == 3
    assert policy["requested_model_is_observed_model"] is False


def test_runtime_model_requires_evidence_and_projects_observed_model(
    rescue_case: SimpleNamespace,
) -> None:
    result = _prepare(
        rescue_case, profile="deep", operation_id="runtime-record-op",
    )
    root = _rescue_root(rescue_case, result)
    _write(
        root / "evidence" / "runtime-model.txt",
        "Observed runtime model: opus; manual fallback observed.\n",
    )
    recorded = record_rescue_runtime(
        rescue_case.run, str(result["rescue_attempt_id"]),
        observed_model="opus", evidence="evidence/runtime-model.txt",
        fallback_observed=True,
    )
    assert recorded["requested_lead_model"] == "opus"
    assert recorded["observed_lead_model"] == "opus"
    assert recorded["fallback_observed"] is True
    shown = show_rescue(rescue_case.run, str(result["rescue_attempt_id"]))
    assert shown["observed_lead_model"] == "opus"
    assert shown["fallback_observed"] is True
    packet = json.loads((root / "RESCUE_PACKET.json").read_text())
    _write_return(
        root, packet, observed_lead_model="opus",
        runtime_observation_evidence="evidence/runtime-model.txt",
        fallback_observed=True,
    )
    validate_rescue_return(
        rescue_case.run, rescue_case.challenge, str(result["rescue_attempt_id"]),
    )


def test_subagent_frontmatter_and_model_limits(rescue_case: SimpleNamespace) -> None:
    assisted = _prepare(
        rescue_case, profile="assisted", operation_id="assisted-op-1",
    )
    root = _rescue_root(rescue_case, assisted)
    expected = {
        "ctf-recon-haiku.md": ("haiku", 6),
        "evidence-triage-haiku.md": ("haiku", 5),
        "exploit-builder-sonnet.md": ("sonnet", 12),
        "alternate-solver-sonnet.md": ("sonnet", 10),
    }
    for name, (model, turns) in expected.items():
        text = (root / ".claude" / "agents" / name).read_text()
        for field in ("name:", "description:", "model:", "tools:", "disallowedTools:", "permissionMode:", "maxTurns:"):
            assert field in text
        assert f"model: {model}" in text
        assert f"maxTurns: {turns}" in text
    assert not (root / ".claude" / "agents" / "clean-room-recon-haiku.md").exists()
    deep = _prepare(
        rescue_case, profile="deep", operation_id="deep-agent-op-1",
    )
    deep_root = _rescue_root(rescue_case, deep)
    assert (deep_root / ".claude" / "agents" / "ctf-recon-haiku.md").is_file()
    assert not (deep_root / ".claude" / "agents" / "clean-room-recon-haiku.md").exists()


def test_packet_does_not_select_sibling_or_other_attempt(rescue_case: SimpleNamespace) -> None:
    sibling = rescue_case.repo / "output" / "demo" / "web" / "sibling" / "secret.txt"
    prior = rescue_case.run.parent / "other-run" / "artifacts" / "prior.txt"
    _write(sibling, "sibling")
    _write(prior, "prior")
    root = _rescue_root(rescue_case, _prepare(rescue_case))
    packet_text = (root / "RESCUE_PACKET.json").read_text()
    assert str(sibling) not in packet_text
    assert str(prior) not in packet_text
    assert not any(path.name in {"secret.txt", "prior.txt"} for path in root.rglob("*"))


@pytest.mark.parametrize("reference", ["/etc/passwd", "../other-run/artifact", "workers/../artifact"])
def test_unsafe_selected_reference_rejected(
    rescue_case: SimpleNamespace, reference: str,
) -> None:
    _write(rescue_case.run / "milestone-receipts.jsonl", json.dumps({
        "event_type": "PRIMITIVE_CONFIRMED", "summary": "claim",
        "evidence": [reference], "artifacts": [],
    }) + "\n")
    with pytest.raises(RescueError, match="safe relative path"):
        _prepare(rescue_case)


def test_symlink_selected_evidence_rejected(rescue_case: SimpleNamespace) -> None:
    evidence = rescue_case.run / "evidence" / "link.txt"
    evidence.parent.mkdir()
    evidence.symlink_to(rescue_case.input_root / "chall")
    _write(rescue_case.run / "milestone-receipts.jsonl", json.dumps({
        "event_type": "PRIMITIVE_CONFIRMED", "summary": "claim",
        "evidence": ["evidence/link.txt"], "artifacts": [],
    }) + "\n")
    with pytest.raises(RescueError, match="symlink"):
        _prepare(rescue_case)


def test_oversized_selected_text_is_manifest_only(rescue_case: SimpleNamespace) -> None:
    evidence = rescue_case.run / "evidence" / "large.txt"
    _write(evidence, "x" * (256 * 1024 + 1))
    _write(rescue_case.run / "milestone-receipts.jsonl", json.dumps({
        "event_type": "PRIMITIVE_CONFIRMED", "summary": "claim",
        "evidence": ["evidence/large.txt"], "artifacts": [],
    }) + "\n")
    root = _rescue_root(rescue_case, _prepare(rescue_case))
    packet = json.loads((root / "RESCUE_PACKET.json").read_text())
    row = packet["evidence"][0]
    assert row["included"] is False
    assert row["size"] == 256 * 1024 + 1
    assert row["sha256"] == hashlib.sha256(evidence.read_bytes()).hexdigest()
    assert row["operator_include_command"].startswith("install -D -m 0400 -- ")
    assert str(root / "work" / "operator-included" / "evidence" / "large.txt") in row["operator_include_command"]
    assert not (root / "context" / "selected" / "evidence" / "large.txt").exists()


def test_truth_levels_come_from_typed_receipts_not_generic_narrative(rescue_case: SimpleNamespace) -> None:
    evidence = rescue_case.run / "evidence" / "primitive.txt"
    _write(evidence, "positive control differs\n")
    receipts = [
        {"receipt_id": "confirmed", "event_type": "PRIMITIVE_CONFIRMED", "summary": "write primitive", "evidence": ["evidence/primitive.txt"], "artifacts": [], "details": {"control_receipt": "evidence/primitive.txt"}},
        {"receipt_id": "candidate", "event_type": "PRIMITIVE_CANDIDATE", "summary": "heap path", "evidence": [], "artifacts": []},
        {"receipt_id": "refuted", "event_type": "PRIMITIVE_REFUTED", "summary": "format string", "evidence": [], "artifacts": []},
        {"receipt_id": "kill", "event_type": "DECISIVE_EXPERIMENT", "summary": "parser family killed", "details": {"decision": "KILL"}, "evidence": [], "artifacts": []},
    ]
    _write(
        rescue_case.run / "milestone-receipts.jsonl",
        "".join(json.dumps(row) + "\n" for row in receipts),
    )
    _write(rescue_case.run / "race-events.jsonl", json.dumps({
        "event_type": "SUPPORTED_FACT", "summary": "narrative only",
    }) + "\n")
    root = _rescue_root(rescue_case, _prepare(rescue_case))
    packet = json.loads((root / "RESCUE_PACKET.json").read_text())
    assert {row["receipt_id"] for row in packet["truth"]["confirmed"]} == {"confirmed"}
    assert "candidate" in {row.get("receipt_id") for row in packet["truth"]["candidates"]}
    assert {"refuted", "kill"}.issubset({row.get("receipt_id") for row in packet["truth"]["refuted"]})
    assert "narrative only" not in json.dumps(packet["truth"])
    roles = {row["path"]: row["role"] for row in packet["source_inventory"]}
    assert roles["milestone-receipts.jsonl"] == "authoritative typed milestones"
    assert roles["race-events.jsonl"] == "auxiliary generic events only"


def test_rescue_ledger_is_strict_and_projection_based(rescue_case: SimpleNamespace) -> None:
    result = _prepare(rescue_case)
    rows = load_rescue_ledger(rescue_case.run)
    assert [row["event"] for row in rows] == [
        "RESCUE_PREPARED", "RESCUE_SANDBOX_CREATING", "RESCUE_SANDBOX_READY",
    ]
    shown = show_rescue(rescue_case.run, str(result["rescue_attempt_id"]))
    assert shown["status"] == "READY"
    assert shown["process_state_inferred"] is False
    ledger = rescue_case.run / "rescue" / "RESCUE_LEDGER.jsonl"
    with ledger.open("a", encoding="utf-8") as handle:
        handle.write("not-json\n")
    with pytest.raises(Exception, match="malformed"):
        load_rescue_ledger(rescue_case.run)


def test_rescue_ledger_rejects_symlink(rescue_case: SimpleNamespace) -> None:
    _prepare(rescue_case, operation_id="ledger-symlink-op")
    ledger = rescue_case.run / "rescue" / "RESCUE_LEDGER.jsonl"
    backup = ledger.with_name("ledger-backup.jsonl")
    ledger.replace(backup)
    ledger.symlink_to(backup)
    with pytest.raises(Exception, match="unsafe"):
        load_rescue_ledger(rescue_case.run)


def test_bind_mount_argv_exposes_only_rescue_writable_paths(rescue_case: SimpleNamespace) -> None:
    prepared = _fake_preparer(**{
        "manifest": rescue_case.manifest, "challenge": rescue_case.challenge,
        "workspace": rescue_case.workspace, "branch": "rescue-fixed",
        "branch_root": rescue_case.run / "rescue" / "rescue-fixed",
        "session_id": "rescue-fixed", "run_id": RUN_ID,
        "rescue_attempt_id": "rescue-fixed", "requested_lead_model": "sonnet",
    })
    for name in ("work", "evidence", "artifacts", "context"):
        (prepared.spec.branch_root / name).mkdir(parents=True, exist_ok=True)
    argv = build_run_argv(prepared.spec)
    joined = "\n".join(argv)
    assert f"src={prepared.spec.source},dst=/challenge,readonly" in joined
    assert f"src={(prepared.spec.branch_root / 'context').resolve()},dst=/context,readonly" in joined
    for name in ("work", "evidence", "artifacts"):
        assert f"src={(prepared.spec.branch_root / name).resolve()},dst=/{name}" in joined
    assert "docker.sock" not in joined
    assert "/.ssh" not in joined
    assert str(rescue_case.repo) not in [arg.split("src=")[-1].split(",")[0] for arg in argv if "src=" in arg]
    assert "ctf-os.session_kind=external-rescue" in joined
    assert "ctf-os.rescue_attempt_id=rescue-fixed" in joined


def test_worker_default_remains_tmpfs(rescue_case: SimpleNamespace) -> None:
    spec = SandboxSpec(
        contest_slug="demo", challenge_id="c", branch="worker-1",
        source=rescue_case.input_root, branch_root=rescue_case.run / "workers" / "worker-1",
        input_fingerprint=FINGERPRINT, input_bytes=15,
        session_id="worker-1", parent_session_id="sol-main", session_role="child",
    )
    (spec.branch_root / "context").mkdir(parents=True)
    argv = build_run_argv(spec)
    assert any(value.startswith("/work:rw") for value in argv)
    assert not any("dst=/work" in value for value in argv)
    assert not any("ctf-os.session_kind" in value for value in argv)


def test_managed_service_rescue_is_attach_only_or_actionable(rescue_case: SimpleNamespace) -> None:
    rescue_case.record["service_plan"] = {"kind": "dockerfile", "dockerfile": "Dockerfile"}
    with pytest.raises(ValueError, match="Sol-owned challenge service"):
        prepare_sandbox_spec(
            repo_root=rescue_case.repo, manifest=rescue_case.manifest,
            challenge=rescue_case.challenge, record=rescue_case.record,
            workspace=rescue_case.workspace, solve_root=rescue_case.run,
            branch="rescue-service", branch_root=rescue_case.run / "rescue" / "rescue-service",
            session_id="rescue-service", parent_session_id="sol-main", session_role="external-rescue",
            require_running_managed_service=True, workspace_mode="bind",
            run_id=RUN_ID, rescue_attempt_id="rescue-service", external_solver=True,
            solver_family="claude", session_kind="external-rescue",
            prepared_fingerprint_reader=lambda _path: "prepared-digest",
            service_inspector=lambda *_args, **_kwargs: {
                "ownership": {}, "containers": [],
                "network": {"exists": False, "owned": False, "internal": False},
            },
        )
    assert "rerun rescue-prepare" in RESCUE_SERVICE_ERROR


def test_active_managed_service_is_sol_owned_attach_only(rescue_case: SimpleNamespace) -> None:
    challenge = replace(rescue_case.challenge, remotes=())
    rescue_case.record["service_plan"] = {"kind": "dockerfile", "dockerfile": "Dockerfile"}
    prepared = prepare_sandbox_spec(
        repo_root=rescue_case.repo, manifest=rescue_case.manifest,
        challenge=challenge, record=rescue_case.record,
        workspace=rescue_case.workspace, solve_root=rescue_case.run,
        branch="rescue-service", branch_root=rescue_case.run / "rescue" / "rescue-service",
        session_id="rescue-service", parent_session_id="sol-main", session_role="external-rescue",
        require_running_managed_service=True, workspace_mode="bind",
        run_id=RUN_ID, rescue_attempt_id="rescue-service", external_solver=True,
        solver_family="claude", session_kind="external-rescue",
        prepared_fingerprint_reader=lambda _path: "prepared-digest",
        service_inspector=lambda *_args, **_kwargs: {
            "ownership": {"state": "RUNNING", "owner_session_id": "sol-main"},
            "containers": [{"state": "running"}],
            "network": {"exists": True, "owned": True, "internal": True},
            "metadata": {"service_endpoints": [{"target": "http://challenge:8080"}]},
        },
    )
    assert prepared.attachment_service is not None
    assert prepared.spec.service_network == prepared.attachment_service.network
    assert prepared.spec.targets == ()
    assert prepared.service_context["lifecycle_owner"] == "sol-main"
    assert prepared.service_context["attach_only"] is True


def _write_return(root: Path, packet: dict[str, object], *, verdict: str = "NO_NEW_PATH", **updates: object) -> dict[str, object]:
    result: dict[str, object] = {
        "schema_version": 1,
        "rescue_attempt_id": packet["identity"]["rescue_attempt_id"],
        "run_id": packet["identity"]["run_id"],
        "challenge_instance_id": packet["identity"]["challenge_instance_id"],
        "input_fingerprint": packet["identity"]["input_fingerprint"],
        "target_revision": packet["identity"]["target_revision"],
        "packet_digest": packet["packet_digest"],
        "requested_lead_model": packet["request"]["requested_lead_model"],
        "observed_lead_model": None,
        "runtime_observation_evidence": None,
        "fallback_observed": None,
        "verdict": verdict,
        "summary": "bounded rescue result",
        "verified_observations": [],
        "new_attack_path": "",
        "decisive_experiments": [],
        "artifacts": [],
        "remote_ready": None,
        "flag_claim": None,
        "message_for_codex": "Continue the exact Solve path.",
    }
    result.update(updates)
    _write(root / "CLAUDE_RETURN.json", result)
    return result


def test_return_digest_and_identity_mismatch_rejected(rescue_case: SimpleNamespace) -> None:
    result = _prepare(rescue_case)
    root = _rescue_root(rescue_case, result)
    packet = json.loads((root / "RESCUE_PACKET.json").read_text())
    _write_return(root, packet, packet_digest="0" * 64)
    with pytest.raises(RescueError, match="packet digest mismatch"):
        validate_rescue_return(rescue_case.run, rescue_case.challenge, str(result["rescue_attempt_id"]))
    _write_return(root, packet, run_id="wrong-run")
    with pytest.raises(RescueError, match="wrong run_id"):
        validate_rescue_return(rescue_case.run, rescue_case.challenge, str(result["rescue_attempt_id"]))


def test_return_rejects_ambiguous_or_unknown_verdict(rescue_case: SimpleNamespace) -> None:
    result = _prepare(rescue_case, operation_id="unknown-verdict-op")
    root = _rescue_root(rescue_case, result)
    packet = json.loads((root / "RESCUE_PACKET.json").read_text())
    _write_return(root, packet, verdict="USEFUL_LEAD")
    with pytest.raises(RescueError, match="verdict is unsupported"):
        validate_rescue_return(
            rescue_case.run, rescue_case.challenge, str(result["rescue_attempt_id"]),
        )


def test_return_rejects_current_target_revision_change(rescue_case: SimpleNamespace) -> None:
    result = _prepare(rescue_case)
    root = _rescue_root(rescue_case, result)
    packet = json.loads((root / "RESCUE_PACKET.json").read_text())
    _write_return(root, packet)
    rescue_case.state["target_revision"] = 2
    _write(rescue_case.run / "STATE.json", rescue_case.state)
    with pytest.raises(RescueError, match="target_revision"):
        validate_rescue_return(rescue_case.run, rescue_case.challenge, str(result["rescue_attempt_id"]))


def test_return_unsafe_artifact_path_rejected(rescue_case: SimpleNamespace) -> None:
    result = _prepare(rescue_case)
    root = _rescue_root(rescue_case, result)
    packet = json.loads((root / "RESCUE_PACKET.json").read_text())
    _write_return(root, packet, artifacts=[{"path": "../artifact", "sha256": "0" * 64}])
    with pytest.raises(RescueError, match="one of"):
        validate_rescue_return(rescue_case.run, rescue_case.challenge, str(result["rescue_attempt_id"]))


def test_return_rejects_missing_and_wrong_artifact_digest(
    rescue_case: SimpleNamespace,
) -> None:
    result = _prepare(rescue_case, operation_id="artifact-digest-op")
    root = _rescue_root(rescue_case, result)
    packet = json.loads((root / "RESCUE_PACKET.json").read_text())
    _write_return(
        root, packet,
        artifacts=[{"path": "artifacts/missing.py", "sha256": "0" * 64}],
    )
    with pytest.raises(RescueError, match="is missing"):
        validate_rescue_return(
            rescue_case.run, rescue_case.challenge, str(result["rescue_attempt_id"]),
        )
    _write(root / "artifacts" / "solve.py", "print('x')\n")
    _write_return(
        root, packet,
        artifacts=[{"path": "artifacts/solve.py", "sha256": "0" * 64}],
    )
    with pytest.raises(RescueError, match="SHA-256 mismatch"):
        validate_rescue_return(
            rescue_case.run, rescue_case.challenge, str(result["rescue_attempt_id"]),
        )


def _remote_flag_result(
    case: SimpleNamespace, root: Path, packet: dict[str, object],
    *, network: bool = True, receipt: bool = True, candidate_in_output: bool = True,
) -> None:
    candidate = "CTF{remote-rescue}"
    artifact = root / "artifacts" / "solve.py"
    _write(artifact, "#!/usr/bin/env python3\n")
    artifact.chmod(0o755)
    evidence = root / "evidence" / "commands" / "command-remote.txt"
    _write(evidence, candidate if candidate_in_output else "no flag\n")
    command_path = root / "RESCUE_COMMANDS.jsonl"
    if receipt:
        command_row = {
            "schema_version": 1,
            "command_receipt_id": "command-remote",
            "run_id": packet["identity"]["run_id"],
            "rescue_attempt_id": packet["identity"]["rescue_attempt_id"],
            "packet_digest": packet["packet_digest"],
            "argv": ["python3", "/artifacts/solve.py", "example.com", "31337"],
            "command_digest": "1" * 64,
            "exit_code": 0,
            "timed_out": False,
            "stdout_digest": "2" * 64,
            "stderr_digest": "3" * 64,
            "authorized_network_observed": network,
            "authorized_network_target_indices": [0],
            "authorized_targets": [{
                "host": "example.com", "port": 31337,
                "protocol": "tcp", "transport": "tcp",
                "ip": "93.184.216.34",
            }],
            "evidence_path": "evidence/commands/command-remote.txt",
            "evidence_digest": hashlib.sha256(evidence.read_bytes()).hexdigest(),
        }
        _write(command_path, json.dumps(command_row, separators=(",", ":")) + "\n")
    _write_return(
        root, packet, verdict="REMOTE_FLAG_OBTAINED",
        artifacts=[{
            "path": "artifacts/solve.py",
            "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            "executable": True,
        }],
        flag_claim={
            "candidate": candidate, "command_receipt_id": "command-remote",
            "exploit_artifact": "artifacts/solve.py",
        },
    )


@pytest.mark.parametrize(
    ("receipt", "network", "candidate_in_output", "message"),
    [
        (False, True, True, "command or session observation receipt"),
        (True, False, True, "authorized network observation"),
        (True, True, False, "candidate is absent"),
    ],
)
def test_remote_flag_requires_receipt_network_and_output(
    rescue_case: SimpleNamespace, receipt: bool, network: bool,
    candidate_in_output: bool, message: str,
) -> None:
    result = _prepare(rescue_case)
    root = _rescue_root(rescue_case, result)
    packet = json.loads((root / "RESCUE_PACKET.json").read_text())
    _remote_flag_result(
        rescue_case, root, packet, receipt=receipt, network=network,
        candidate_in_output=candidate_in_output,
    )
    with pytest.raises(RescueError, match=message):
        validate_rescue_return(rescue_case.run, rescue_case.challenge, str(result["rescue_attempt_id"]))


def test_remote_flag_validation_creates_resume_only(rescue_case: SimpleNamespace) -> None:
    result = _prepare(rescue_case)
    root = _rescue_root(rescue_case, result)
    packet = json.loads((root / "RESCUE_PACKET.json").read_text())
    _remote_flag_result(rescue_case, root, packet)
    protected = {
        "state": (rescue_case.run / "STATE.json").read_bytes(),
        "candidates": (rescue_case.run / "candidates.json").read_bytes(),
        "milestones": (rescue_case.run / "milestone-receipts.jsonl").read_bytes()
        if (rescue_case.run / "milestone-receipts.jsonl").exists() else None,
    }
    validation = validate_rescue_return(
        rescue_case.run, rescue_case.challenge, str(result["rescue_attempt_id"]),
    )
    assert validation["milestone_or_flag_receipt_created"] is False
    assert (rescue_case.run / "STATE.json").read_bytes() == protected["state"]
    assert (rescue_case.run / "candidates.json").read_bytes() == protected["candidates"]
    assert not (rescue_case.run / "flag-receipts").exists()
    resume = (root / "CODEX-RESUME.md").read_text()
    assert "candidate insight" in resume
    assert "rescue-flag-promote" in resume
    assert "--contest demo" in resume


def test_remote_flag_rejects_declared_target_mismatch_and_bad_pattern(
    rescue_case: SimpleNamespace,
) -> None:
    result = _prepare(rescue_case, operation_id="remote-mismatch-op")
    root = _rescue_root(rescue_case, result)
    packet = json.loads((root / "RESCUE_PACKET.json").read_text())
    _remote_flag_result(rescue_case, root, packet)
    receipt = json.loads((root / "RESCUE_COMMANDS.jsonl").read_text())
    receipt["authorized_network_target_indices"] = [1]
    _write(root / "RESCUE_COMMANDS.jsonl", json.dumps(receipt) + "\n")
    with pytest.raises(RescueError, match="target mismatch"):
        validate_rescue_return(
            rescue_case.run, rescue_case.challenge, str(result["rescue_attempt_id"]),
        )
    receipt["authorized_network_target_indices"] = [0]
    _write(root / "RESCUE_COMMANDS.jsonl", json.dumps(receipt) + "\n")
    returned = json.loads((root / "CLAUDE_RETURN.json").read_text())
    returned["flag_claim"]["candidate"] = "not-a-flag"
    _write(root / "CLAUDE_RETURN.json", returned)
    with pytest.raises(RescueError, match="flag pattern"):
        validate_rescue_return(
            rescue_case.run, rescue_case.challenge, str(result["rescue_attempt_id"]),
        )


def test_remote_ready_handoff_requires_executable_and_one_to_three(rescue_case: SimpleNamespace) -> None:
    result = _prepare(rescue_case)
    root = _rescue_root(rescue_case, result)
    packet = json.loads((root / "RESCUE_PACKET.json").read_text())
    artifact = root / "artifacts" / "solve.py"
    _write(artifact, "#!/usr/bin/env python3\n")
    artifact.chmod(0o755)
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    _write_return(
        root, packet, verdict="REMOTE_READY_HANDOFF",
        artifacts=[{"path": "artifacts/solve.py", "sha256": digest, "executable": True}],
        remote_ready={
            "value": True,
            "exploit_artifact": "artifacts/solve.py",
            "exploit_artifact_sha256": digest,
            "exact_next_argv": ["python3", "/artifacts/solve.py", "example.com", "31337"],
            "target_index": 0,
            "success_condition": "flag appears in output",
            "kill_condition": "remote rejects framing",
            "maximum_remaining_experiments": 3,
        },
    )
    validate_rescue_return(rescue_case.run, rescue_case.challenge, str(result["rescue_attempt_id"]))
    resume = (root / "CODEX-RESUME.md").read_text()
    assert "Maximum decisive experiments: 3" in resume
    assert "Success condition" in resume and "Kill condition" in resume
    assert not (rescue_case.run / "flag-receipts").exists()


def test_remote_ready_rejects_unrelated_artifact_argv(rescue_case: SimpleNamespace) -> None:
    result = _prepare(rescue_case, operation_id="remote-ready-unlinked")
    root = _rescue_root(rescue_case, result)
    packet = json.loads((root / "RESCUE_PACKET.json").read_text())
    artifact = root / "artifacts" / "solve.py"
    _write(artifact, "#!/usr/bin/env python3\n")
    artifact.chmod(0o755)
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    _write_return(
        root, packet, verdict="REMOTE_READY_HANDOFF",
        artifacts=[{"path": "artifacts/solve.py", "sha256": digest, "executable": True}],
        remote_ready={
            "value": True, "exploit_artifact": "artifacts/solve.py",
            "exploit_artifact_sha256": digest,
            "exact_next_argv": ["python3", "/work/unrelated.py"],
            "target_index": 0, "success_condition": "flag", "kill_condition": "reject",
            "maximum_remaining_experiments": 1,
        },
    )
    with pytest.raises(RescueError, match="not linked"):
        validate_rescue_return(
            rescue_case.run, rescue_case.challenge, str(result["rescue_attempt_id"]),
        )


@pytest.mark.parametrize("maximum", [0, 4])
def test_remote_ready_rejects_out_of_range_experiment_bound(
    rescue_case: SimpleNamespace, maximum: int,
) -> None:
    result = _prepare(
        rescue_case, operation_id=f"remote-ready-bound-{maximum}",
    )
    root = _rescue_root(rescue_case, result)
    packet = json.loads((root / "RESCUE_PACKET.json").read_text())
    artifact = root / "artifacts" / "solve.py"
    _write(artifact, "#!/usr/bin/env python3\n")
    artifact.chmod(0o755)
    _write_return(
        root, packet, verdict="REMOTE_READY_HANDOFF",
        artifacts=[{
            "path": "artifacts/solve.py",
            "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            "executable": True,
        }],
        remote_ready={
            "value": True, "exploit_artifact": "artifacts/solve.py",
            "exploit_artifact_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            "exact_next_argv": ["python3", "/artifacts/solve.py"],
            "target_index": 0, "success_condition": "flag",
            "kill_condition": "rejected",
            "maximum_remaining_experiments": maximum,
        },
    )
    with pytest.raises(RescueError, match="1 through 3"):
        validate_rescue_return(
            rescue_case.run, rescue_case.challenge, str(result["rescue_attempt_id"]),
        )


def test_return_validation_is_idempotent_but_changed_return_conflicts(rescue_case: SimpleNamespace) -> None:
    result = _prepare(rescue_case)
    root = _rescue_root(rescue_case, result)
    packet = json.loads((root / "RESCUE_PACKET.json").read_text())
    _write_return(root, packet)
    first = validate_rescue_return(
        rescue_case.run, rescue_case.challenge, str(result["rescue_attempt_id"]),
    )
    second = validate_rescue_return(
        rescue_case.run, rescue_case.challenge, str(result["rescue_attempt_id"]),
    )
    assert first["idempotent"] is False and second["idempotent"] is True
    _write_return(root, packet, summary="changed result after validation")
    with pytest.raises(RescueError, match="validated Claude return changed"):
        validate_rescue_return(
            rescue_case.run, rescue_case.challenge, str(result["rescue_attempt_id"]),
        )


def test_close_cleans_exact_rescue_and_preserves_workspace(rescue_case: SimpleNamespace) -> None:
    result = _prepare(rescue_case)
    root = _rescue_root(rescue_case, result)
    seen: list[tuple[str, str, str]] = []

    def fake_cleanup(metadata: dict[str, object], **kwargs: object) -> dict[str, object]:
        seen.append((str(metadata["rescue_attempt_id"]), str(kwargs["session_id"]), str(kwargs["session_role"])))
        return {"container": metadata["name"], "removed": True}

    closed = close_rescue(
        rescue_case.run, str(result["rescue_attempt_id"]), outcome="manual",
        sandbox_cleanup=fake_cleanup,
    )
    assert closed["closed"] is True and closed["workspace_preserved"] is True
    assert seen == [(str(result["rescue_attempt_id"]), str(result["rescue_attempt_id"]), "external-rescue")]
    assert root.is_dir() and (root / "RESCUE_PACKET.json").is_file()
    assert load_rescue_ledger(rescue_case.run)[-1]["event"] == "RESCUE_CLOSED"


def test_close_is_cleanup_only_after_run_is_sealed(rescue_case: SimpleNamespace) -> None:
    result = _prepare(rescue_case, operation_id="sealed-cleanup-op")
    rescue_case.state["sealed"] = True
    rescue_case.state["status"] = "SEALED"
    _write(rescue_case.run / "STATE.json", rescue_case.state)
    closed = close_rescue(
        rescue_case.run, str(result["rescue_attempt_id"]), outcome="manual",
        sandbox_cleanup=lambda metadata, **_kwargs: {
            "container": metadata["name"], "removed": True,
        },
    )
    assert closed["closed"] is True
    assert rescue_case.state["status"] == "SEALED"


def test_close_rejects_unknown_evidence_receipt(rescue_case: SimpleNamespace) -> None:
    result = _prepare(rescue_case, operation_id="close-evidence-op")
    with pytest.raises(RescueError, match="does not exist"):
        close_rescue(
            rescue_case.run, str(result["rescue_attempt_id"]), outcome="integrated",
            evidence_receipt_id="missing-receipt",
            sandbox_cleanup=lambda *_args, **_kwargs: {},
        )


def test_close_integrated_accepts_exact_command_observation(rescue_case: SimpleNamespace) -> None:
    result = _prepare(rescue_case, operation_id="close-command-evidence")
    root = _rescue_root(rescue_case, result)
    packet = json.loads((root / "RESCUE_PACKET.json").read_text())
    receipt = _record_command_receipt(
        rescue_case.run, root, packet, ["python3", "probe.py"],
        {
            "exit_code": 0, "timed_out": False, "stdout": "decisive output\n",
            "stderr": "", "authorized_network_observed": False,
            "authorized_network_target_indices": [], "authorized_targets": [],
        }, before_artifacts=_artifact_snapshot(root),
    )
    closed = close_rescue(
        rescue_case.run, str(result["rescue_attempt_id"]), outcome="integrated",
        evidence_receipt_id=str(receipt["command_receipt_id"]),
        sandbox_cleanup=lambda *_args, **_kwargs: {"removed": True},
    )
    assert closed["closed"] is True and closed["outcome"] == "integrated"
    events = [row["event"] for row in load_rescue_ledger(rescue_case.run)]
    assert "RESCUE_CONFIRMED" in events


def test_close_rescue_without_created_sandbox_preserves_workspace(
    rescue_case: SimpleNamespace,
) -> None:
    operation = "pre-sandbox-failure"

    def fail_create(_spec: SandboxSpec) -> dict[str, object]:
        raise RuntimeError("synthetic create failure")

    with pytest.raises(RuntimeError, match="synthetic"):
        _prepare(rescue_case, operation_id=operation, sandbox_factory=fail_create)
    rescue_id = rescue_attempt_id(RUN_ID, operation)
    root = (
        rescue_case.claude_home / "runs" / "demo" / "pwn" /
        "challenge-001" / RUN_ID / rescue_id
    )
    assert root.is_dir() and not (root / "sandbox.json").exists()
    closed = close_rescue(rescue_case.run, rescue_id, outcome="manual")
    assert closed["cleanup_receipt"]["sandbox_cleanup"] == "NOT_PRESENT"
    assert closed["workspace_preserved"] is True


def test_ctf_tool_command_receipt_and_repetition_advisory(
    rescue_case: SimpleNamespace,
) -> None:
    result = _prepare(rescue_case, operation_id="command-receipt-op")
    root = _rescue_root(rescue_case, result)
    packet = json.loads((root / "RESCUE_PACKET.json").read_text())
    before = _artifact_snapshot(root)
    execution = {
        "exit_code": 0, "timed_out": False,
        "stdout": "proof\n", "stderr": "",
        "authorized_network_observed": False,
        "authorized_network_target_indices": [],
        "authorized_targets": [],
    }
    first = _record_command_receipt(
        rescue_case.run, root, packet, ["python3", "probe.py"], execution,
        before_artifacts=before,
    )
    second = _record_command_receipt(
        rescue_case.run, root, packet, ["python3", "probe.py"], execution,
        before_artifacts=before,
    )
    assert first["repeated_command_warning"] is False
    assert second["repeated_command_warning"] is True
    assert (root / first["evidence_path"]).is_file()
    receipts = [json.loads(line) for line in (root / "RESCUE_COMMANDS.jsonl").read_text().splitlines()]
    assert len(receipts) == 2
    events = [row["event"] for row in load_rescue_ledger(rescue_case.run)]
    assert events.count("RESCUE_COMMAND_RECORDED") == 2


def test_confirmed_breakthrough_requires_positive_command_receipt(
    rescue_case: SimpleNamespace,
) -> None:
    result = _prepare(rescue_case, operation_id="breakthrough-receipt-op")
    root = _rescue_root(rescue_case, result)
    packet = json.loads((root / "RESCUE_PACKET.json").read_text())
    _write_return(
        root, packet, verdict="CONFIRMED_BREAKTHROUGH",
        decisive_experiments=[{
            "decision": "CONFIRMED", "observed_result": "control differs",
        }],
    )
    with pytest.raises(RescueError, match="decisive evidence"):
        validate_rescue_return(
            rescue_case.run, rescue_case.challenge, str(result["rescue_attempt_id"]),
        )
    receipt = _record_command_receipt(
        rescue_case.run, root, packet, ["python3", "probe.py"],
        {
            "exit_code": 0, "timed_out": False, "stdout": "control differs\n",
            "stderr": "", "authorized_network_observed": False,
            "authorized_network_target_indices": [], "authorized_targets": [],
        },
        before_artifacts=_artifact_snapshot(root),
    )
    _write_return(
        root, packet, verdict="CONFIRMED_BREAKTHROUGH",
        decisive_experiments=[{
            "command_receipt_id": receipt["command_receipt_id"],
            "decision": "CONFIRMED", "observed_result": "control differs",
            "success_condition": "target only changes",
            "kill_condition": "control also changes",
        }],
    )
    validated = validate_rescue_return(
        rescue_case.run, rescue_case.challenge, str(result["rescue_attempt_id"]),
    )
    assert validated["verdict"] == "CONFIRMED_BREAKTHROUGH"


def test_ctf_tool_identity_is_fixed_and_paths_are_safe(rescue_case: SimpleNamespace) -> None:
    result = _prepare(rescue_case)
    root = _rescue_root(rescue_case, result)
    wrapper = (root / "ctf-tool").read_text()
    assert f"CTF_OS_RESCUE_RUN_ID={RUN_ID}" in wrapper
    assert f"CTF_OS_RESCUE_ID={result['rescue_attempt_id']}" in wrapper
    assert f"CTF_OS_RESCUE_PACKET_DIGEST={result['packet_digest']}" in wrapper
    assert "python -m ctf_os.rescue_tool" in wrapper
    assert "session|progress|task|knowledge|sandbox|hook|mcp-serve" in wrapper
    assert '"$@"' in wrapper
    for unsafe in ("/absolute", "../parent", "dir/../parent", "."):
        with pytest.raises(RescueError):
            _safe_relative(unsafe)


def test_ctf_tool_import_rejects_input_symlink(rescue_case: SimpleNamespace) -> None:
    link = rescue_case.input_root / "linked"
    link.symlink_to(rescue_case.input_root / "chall")
    with pytest.raises(RescueError, match="symlink"):
        _input_files(rescue_case.input_root, relative="linked", all_bounded=False)


def test_ctf_tool_import_records_copy_result_hashes(
    rescue_case: SimpleNamespace, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import ctf_os.rescue_tool as rescue_tool

    rescue_root = rescue_case.run / "rescue" / "rescue-import"
    (rescue_root / "logs").mkdir(parents=True)
    expected = [{
        "path": "chall", "size": 15,
        "sha256": hashlib.sha256((rescue_case.input_root / "chall").read_bytes()).hexdigest(),
    }]

    def fake_execute(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {"exit_code": 0, "stdout": json.dumps(expected, sort_keys=True, separators=(",", ":"))}

    monkeypatch.setattr(rescue_tool, "execute", fake_execute)
    result = _import_input(
        rescue_case.run, rescue_root,
        {
            "source": str(rescue_case.input_root),
            "resource_profile": "standard",
            "rescue_attempt_id": "rescue-import",
        },
        relative="chall", all_bounded=False,
    )
    assert result["manifest"] == expected
    receipt = json.loads((rescue_root / "logs" / "input-imports.jsonl").read_text())
    assert receipt["files"] == receipt["copy_results"] == expected


@pytest.mark.parametrize(
    "argv",
    [
        ["claude", "--model", "sonnet"],
        ["/usr/local/bin/codex"],
        ["python3", "-m", "anthropic"],
        ["bash", "-c", "claude --model opus"],
    ],
)
def test_ctf_tool_rejects_model_process_commands(argv: list[str]) -> None:
    with pytest.raises(RescueError, match="model process|shell strings"):
        _reject_model_command(argv)


def test_ctf_tool_rejects_generic_shell_string() -> None:
    with pytest.raises(RescueError, match="shell strings"):
        _reject_model_command(["bash", "-c", "id && uname -a"])


def test_prepare_never_launches_model_process(
    rescue_case: SimpleNamespace, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import subprocess

    original = subprocess.run

    def guarded(argv: object, *args: object, **kwargs: object) -> object:
        first = str(list(argv)[0]).casefold()
        if first in {"claude", "codex"}:
            raise AssertionError("model process launch attempted")
        return original(argv, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", guarded)
    result = _prepare(rescue_case)
    assert result["claude_process_started"] is False
    source = (rescue_case.repo / "ctf_os" / "rescue.py")
    assert not source.exists()  # fixture repo contains only generated run data


def test_benchmark_contract_has_no_rescue_arm() -> None:
    text = Path("docs/SOLVER_BENCHMARK.md").read_text(encoding="utf-8")
    assert "| A | plain Sol |" in text
    assert "| B | CTF-OS `sol-only` |" in text
    assert "| C | CTF-OS `fixed-race` |" in text
    assert "| D | CTF-OS `adaptive-race` |" in text
    assert not re.search(r"(?:arm|treatment).*Claude rescue", text, re.I)


def _v3_backend(
    case: SimpleNamespace, result: dict[str, object],
) -> tuple[Path, dict[str, object], dict[str, object], RescueBackend]:
    root = _rescue_root(case, result)
    packet = json.loads((root / "RESCUE_PACKET.json").read_text())
    metadata = json.loads((root / "sandbox.json").read_text())
    return root, packet, metadata, RescueBackend(case.run, root, metadata, packet)


def test_v2_packet_research_policy_and_v1_read_compatibility(
    rescue_case: SimpleNamespace,
) -> None:
    result = _prepare(
        rescue_case, operation_id="v2-research", research_policy="public-web",
    )
    root, packet, _metadata, _backend = _v3_backend(rescue_case, result)
    assert packet["schema_version"] == 2
    assert packet["research_policy"] == "public-web"
    assert packet["external_research_allowed"] is True
    settings = json.loads((root / ".claude" / "settings.json").read_text())
    assert settings["permissions"]["defaultMode"] == "default"
    assert "WebSearch" in settings["permissions"]["allow"]
    assert set((
        "SessionStart", "PreCompact", "PostCompact", "SessionEnd",
        "SubagentStart", "SubagentStop", "TaskCreated", "TaskCompleted",
    )).issubset(settings["hooks"])
    legacy = dict(packet)
    legacy["schema_version"] = 1
    legacy["packet_digest"] = calculate_packet_digest(legacy)
    (root / "RESCUE_PACKET.json").chmod(0o600)
    _write(root / "RESCUE_PACKET.json", legacy)
    assert _load_packet(root)["schema_version"] == 1


def test_progress_task_and_knowledge_typed_ledgers(rescue_case: SimpleNamespace) -> None:
    result = _prepare(rescue_case, operation_id="typed-ledgers")
    root, packet, _metadata, backend = _v3_backend(rescue_case, result)
    for number in (1, 2):
        backend.progress_record({
            "event": "HYPOTHESIS_OPENED", "hypothesis_id": f"hyp-{number}",
            "summary": f"candidate {number}",
        })
    with pytest.raises(RescueError, match="limit is 2"):
        backend.progress_record({
            "event": "HYPOTHESIS_OPENED", "hypothesis_id": "hyp-3",
            "summary": "too many",
        })
    with pytest.raises(RescueError, match="success and kill"):
        backend.progress_record({"event": "EXPERIMENT_PLANNED", "experiment_id": "exp-1"})
    artifact = root / "artifacts" / "typed.py"
    _write(artifact, "print('typed')\n")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    task = {
        "task_id": "task-1", "role": "exploit-builder", "objective": "build PoC",
        "success_condition": "artifact runs", "kill_condition": "primitive fails",
        "maximum_turns": 10, "expected_artifacts": ["artifacts/typed.py"],
        "allowed_hypothesis_family": "overflow", "forbidden_repeated_paths": [],
    }
    backend.task_create(task)
    backend.task_result({
        "task_id": "task-1", "status": "SUPPORTED", "summary": "artifact ready",
        "command_receipt_ids": [], "session_observation_receipt_ids": [],
        "artifacts": [{"path": "artifacts/typed.py", "sha256": digest}],
        "evidence": [], "recommended_next_action": "run remote",
    })
    source = backend.knowledge_source_record({
        "query": "version exploit", "tool": "WebSearch", "source_title": "source",
        "source_url_or_resource_id": "https://example.test/source",
        "bounded_excerpt": "candidate technique", "content_digest": "0" * 64,
        "session_id": "claude-session", "subagent_id": "",
    })
    hint = backend.knowledge_hint_record({
        "query": "version exploit", "source_receipt_ids": [source["receipt_id"]],
        "atomic_attack_facts": ["fact"], "applicability_conditions": ["version matches"],
        "current_challenge_matches": ["banner matches"], "proposed_attack_path": "try primitive",
        "decisive_experiment": {
            "argv_or_session_plan": {"argv": ["python3", "probe.py"]},
            "success_condition": "control differs", "kill_condition": "control matches",
        },
        "status": "CANDIDATE",
    })
    assert hint["payload"]["status"] == "CANDIDATE"
    assert backend.progress_show()["active_hypotheses"][0]["hypothesis_id"] == "hyp-1"


def test_session_cursor_binary_send_and_observation_receipt(
    rescue_case: SimpleNamespace, monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _prepare(rescue_case, operation_id="session-unit")
    root, packet, metadata, _backend = _v3_backend(rescue_case, result)
    manager = RescueSessionManager(rescue_case.run, root, metadata, packet)
    monkeypatch.setattr(manager, "_network_counters", lambda: None)

    def fake_open(
        session_id: str, _kind: str, argv: list[str], directory: Path,
    ) -> dict[str, object]:
        _write(directory / "control" / "cursor_base", "0\n")
        return {"backend": "tmux", "backend_id": "fake", "argv": argv}

    sent: list[bytes] = []
    monkeypatch.setattr(manager.backend, "open_pty", fake_open)
    monkeypatch.setattr(manager.backend, "status", lambda *_args: {"status": "RUNNING"})
    monkeypatch.setattr(manager.backend, "send_pty", lambda _sid, data: sent.append(data))
    monkeypatch.setattr(manager.backend, "close", lambda *_args: {"termination_exit_code": 0, "remaining_processes": []})
    opened = manager.open(kind="shell", name="main-shell", argv=["/bin/bash"])
    session_id = str(opened["session_id"])
    manager.send(session_id, b"\x00\x01\xff", encoding="hex")
    assert sent == [b"\x00\x01\xff"]
    directory = root / "sessions" / session_id
    (directory / "stdout.bin").write_bytes(b"hello\x00\xff")
    observed = manager.read(session_id, cursor=0, max_bytes=32)
    assert observed["stdout"] is None
    assert base64.b64decode(observed["stdout_base64"]) == b"hello\x00\xff"
    rows = [json.loads(line) for line in (root / "RESCUE_SESSIONS.jsonl").read_text().splitlines()]
    output = [row for row in rows if row["event"] == "SESSION_OUTPUT_OBSERVED"][-1]
    assert output["observation_receipt_id"] == observed["observation_receipt_id"]
    assert output["cursor_before"] == 0 and output["cursor_after"] == 7
    assert manager.close(session_id)["status"] == "CLOSED"


def test_hook_model_resume_compaction_and_offline_research(
    rescue_case: SimpleNamespace,
) -> None:
    result = _prepare(rescue_case, operation_id="hook-events", research_policy="offline")
    root, _packet, _metadata, backend = _v3_backend(rescue_case, result)
    started = handle_hook(backend, "SessionStart", {
        "hook_event_name": "SessionStart", "session_id": "claude-session-1",
        "model": "claude-opus-4-8", "source": "startup",
        "transcript_path": "/tmp/transcript.jsonl", "cwd": str(root),
    })
    assert "bounded resume context" in started["hookSpecificOutput"]["additionalContext"]
    shown = show_rescue(rescue_case.run, str(result["rescue_attempt_id"]))
    assert shown["claude_session_id"] == "claude-session-1"
    assert shown["claude_resume_command"] == "claude --resume 'claude-session-1'"
    compact = handle_hook(backend, "PreCompact", {
        "hook_event_name": "PreCompact", "session_id": "claude-session-1", "trigger": "auto",
    })
    assert compact["checkpoint_present"] is False
    blocked = handle_hook(backend, "PreToolUse", {
        "hook_event_name": "PreToolUse", "session_id": "claude-session-1",
        "tool_name": "WebSearch", "tool_input": {"query": "exact challenge"},
    })
    assert blocked["hookSpecificOutput"]["permissionDecision"] == "deny"
    handle_hook(backend, "PostCompact", {
        "hook_event_name": "PostCompact", "session_id": "claude-session-1",
        "trigger": "auto", "compact_summary": "bounded summary",
    })
    handle_hook(backend, "SessionEnd", {
        "hook_event_name": "SessionEnd", "session_id": "claude-session-1",
        "reason": "prompt_input_exit",
    })
    rows = [json.loads(line) for line in (root / "CLAUDE_SESSION_EVENTS.jsonl").read_text().splitlines()]
    assert rows[-1]["duration_seconds"] is not None


def test_hook_resume_subagent_task_and_web_source_capture(
    rescue_case: SimpleNamespace,
) -> None:
    result = _prepare(
        rescue_case, operation_id="hook-extended", research_policy="public-web",
    )
    root, _packet, _metadata, backend = _v3_backend(rescue_case, result)
    backend.task_create({
        "task_id": "task-hook", "role": "recon", "objective": "check banner",
        "success_condition": "version identified", "kill_condition": "no banner",
        "maximum_turns": 3, "expected_artifacts": [],
        "allowed_hypothesis_family": "version", "forbidden_repeated_paths": [],
    })
    handle_hook(backend, "SessionStart", {
        "hook_event_name": "SessionStart", "session_id": "claude-session-resume",
        "model": "claude-sonnet-4-6", "source": "resume",
        "transcript_path": "/tmp/resume.jsonl", "cwd": str(root),
    })
    handle_hook(backend, "SubagentStart", {
        "hook_event_name": "SubagentStart", "session_id": "claude-session-resume",
        "agent_id": "agent-1", "agent_type": "ctf-recon-haiku",
    })
    handle_hook(backend, "TaskCreated", {
        "hook_event_name": "TaskCreated", "session_id": "claude-session-resume",
        "task_id": "task-hook",
    })
    captured = handle_hook(backend, "PostToolUse", {
        "hook_event_name": "PostToolUse", "session_id": "claude-session-resume",
        "agent_id": "agent-1", "tool_name": "WebSearch",
        "tool_input": {"query": "library version behavior"},
        "tool_response": {"title": "bounded source", "url": "https://example.test"},
    })
    handle_hook(backend, "TaskCompleted", {
        "hook_event_name": "TaskCompleted", "session_id": "claude-session-resume",
        "task_id": "task-hook",
    })
    handle_hook(backend, "SubagentStop", {
        "hook_event_name": "SubagentStop", "session_id": "claude-session-resume",
        "agent_id": "agent-1", "agent_type": "ctf-recon-haiku",
    })
    assert captured["recorded"] is True
    hooks = [json.loads(line) for line in (root / "CLAUDE_SESSION_EVENTS.jsonl").read_text().splitlines()]
    assert hooks[0]["source"] == "resume"
    assert {row["event"] for row in hooks}.issuperset({
        "SessionStart", "SubagentStart", "SubagentStop", "TaskCreated", "TaskCompleted",
    })
    tasks = [json.loads(line) for line in (root / "RESCUE_TASKS.jsonl").read_text().splitlines()]
    assert {row["event"] for row in tasks}.issuperset({"TASK_STARTED", "TASK_CLOSED"})
    sources = [json.loads(line) for line in (root / "KNOWLEDGE_SOURCES.jsonl").read_text().splitlines()]
    assert sources[-1]["payload"]["tool"] == "WebSearch"


def test_mcp_initialize_tools_list_and_fixed_backend(rescue_case: SimpleNamespace) -> None:
    result = _prepare(rescue_case, operation_id="mcp-tools")
    _root, _packet, _metadata, backend = _v3_backend(rescue_case, result)
    server = StdioMCPServer(backend, lambda *_args: {"unused": True})
    initialized = server.handle({
        "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {},
    })
    assert initialized["result"]["serverInfo"]["name"] == "ctf-rescue"
    listed = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = {row["name"] for row in listed["result"]["tools"]}
    assert {
        "ctf_inventory", "ctf_exec", "ctf_session_open", "ctf_session_read",
        "ctf_progress_record", "ctf_task_result", "ctf_knowledge_hint_record",
    }.issubset(names)


def test_generated_mcp_server_uses_real_stdio_protocol(rescue_case: SimpleNamespace) -> None:
    result = _prepare(rescue_case, operation_id="mcp-stdio")
    root = _rescue_root(rescue_case, result)
    preflight_path = rescue_case.workspace / "CHALLENGE-PREFLIGHT.json"
    preflight = json.loads(preflight_path.read_text())
    preflight["prepared_fingerprint"] = prepared_tree_fingerprint(rescue_case.input_root)
    _write(preflight_path, preflight)
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "ctf_progress_show", "arguments": {}},
        },
    ]
    completed = subprocess.run(
        [str(root / "ctf-tool"), "mcp-serve"],
        input="".join(json.dumps(row) + "\n" for row in requests),
        capture_output=True, text=True, timeout=20, check=False,
    )
    assert completed.returncode == 0, completed.stderr
    responses = [json.loads(line) for line in completed.stdout.splitlines()]
    assert [row["id"] for row in responses] == [1, 2, 3]
    assert responses[0]["result"]["serverInfo"]["name"] == "ctf-rescue"
    content = json.loads(responses[-1]["result"]["content"][0]["text"])
    assert content["ok"] is True
    assert content["result"]["run_id"] == RUN_ID


def test_exact_rescue_flag_promotion_uses_preserved_receipt(
    rescue_case: SimpleNamespace,
) -> None:
    result = _prepare(rescue_case, operation_id="exact-flag-promotion")
    root = _rescue_root(rescue_case, result)
    packet = json.loads((root / "RESCUE_PACKET.json").read_text())
    _remote_flag_result(rescue_case, root, packet)
    promoted = promote_rescue_flag(
        rescue_case.run, rescue_case.challenge, str(result["rescue_attempt_id"]),
        execution_receipt_id="command-remote", candidate="CTF{remote-rescue}",
        exploit_artifact="artifacts/solve.py",
    )
    receipt = json.loads(Path(promoted["receipt"]).read_text())
    assert receipt["source_type"] == "CLAUDE_RESCUE"
    assert receipt["rescue_attempt_id"] == result["rescue_attempt_id"]
    assert receipt["execution_receipt_id"] == "command-remote"


@pytest.mark.skipif(
    os.environ.get("CTF_OS_DOCKER_SMOKE") != "1",
    reason="explicit local/CI gate: set CTF_OS_DOCKER_SMOKE=1 after building ctf-os-sandbox:pwn",
)
def test_real_docker_rescue_runtime_and_session_flag_promotion(
    rescue_case: SimpleNamespace,
) -> None:
    docker_info = subprocess.run(
        ["docker", "info", "--format", "{{.ServerVersion}}"],
        capture_output=True, text=True, timeout=20, check=False,
    )
    assert docker_info.returncode == 0, "real Docker daemon is required: " + docker_info.stderr
    image = subprocess.run(
        ["docker", "image", "inspect", "ctf-os-sandbox:pwn"],
        capture_output=True, text=True, timeout=20, check=False,
    )
    assert image.returncode == 0, "build ctf-os-sandbox:pwn before the Docker smoke gate"

    suffix = hashlib.sha256(str(rescue_case.run).encode()).hexdigest()[:10]
    target_name = f"ctf-os-rescue-target-{suffix}"
    target_started = subprocess.run([
        "docker", "run", "--detach", "--name", target_name, "--network", "bridge",
        "--entrypoint", "/bin/sh", "ctf-os-sandbox:pwn", "-c",
        "socat TCP4-LISTEN:31337,reuseaddr,fork EXEC:/bin/cat & "
        "socat UDP4-RECVFROM:31338,reuseaddr,fork EXEC:/bin/cat & wait",
    ], capture_output=True, text=True, timeout=30, check=False)
    assert target_started.returncode == 0, target_started.stderr
    metadata: dict[str, object] | None = None
    result: dict[str, object] | None = None
    mcp: subprocess.Popen[str] | None = None
    try:
        inspected = subprocess.run([
            "docker", "inspect", target_name, "--format",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
        ], capture_output=True, text=True, timeout=20, check=False)
        assert inspected.returncode == 0 and inspected.stdout.strip(), inspected.stderr
        target_ip = inspected.stdout.strip()
        result = _prepare(rescue_case, operation_id="real-docker-runtime")
        root = _rescue_root(rescue_case, result)
        packet = json.loads((root / "RESCUE_PACKET.json").read_text())
        rescue_id = str(result["rescue_attempt_id"])
        tcp_target = ResolvedTarget(Target(
            "tcp://example.com:31337", "example.com", 31337, "tcp",
            organizer_declared=True,
        ), target_ip)
        udp_target = ResolvedTarget(Target(
            "udp://udp-smoke.test:31338", "udp-smoke.test", 31338, "udp",
            organizer_declared=True,
        ), target_ip)
        spec = SandboxSpec(
            contest_slug="demo", challenge_id=rescue_case.challenge.id,
            branch=rescue_id, source=rescue_case.input_root, branch_root=root,
            input_fingerprint=FINGERPRINT, target_revision=1,
            targets=(tcp_target, udp_target), image="ctf-os-sandbox:pwn",
            resource_profile="light", category="pwn", workspace_mode="bind",
            run_id=RUN_ID, rescue_attempt_id=rescue_id, external_solver=True,
            solver_family="claude", session_id=rescue_id,
            parent_session_id="sol-main", session_role="external-rescue",
            session_kind="external-rescue", requested_lead_model="sonnet",
        )
        metadata = create_sandbox(spec)
        adopted = create_sandbox(spec)
        assert adopted["name"] == metadata["name"]
        metadata["packet_digest"] = packet["packet_digest"]
        _write(root / "sandbox.json", metadata)
        preflight_path = rescue_case.workspace / "CHALLENGE-PREFLIGHT.json"
        preflight = json.loads(preflight_path.read_text())
        preflight["prepared_fingerprint"] = prepared_tree_fingerprint(rescue_case.input_root)
        _write(preflight_path, preflight)
        backend = RescueBackend(rescue_case.run, root, metadata, packet)
        inventory = backend.inventory(refresh=True)
        required = {
            row["name"] for row in inventory["installed_tools"]
            if row["classification"] == "REQUIRED" and row["available"]
        }
        assert {"gdb", "python3", "tmux"}.issubset(required)
        assert inventory["actual_image_id"]

        mcp = subprocess.Popen(
            [str(root / "ctf-tool"), "mcp-serve"], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        assert mcp.stdin is not None and mcp.stdout is not None
        mcp_id = 0

        def mcp_request(method: str, params: dict[str, object]) -> dict[str, object]:
            nonlocal mcp_id
            mcp_id += 1
            mcp.stdin.write(json.dumps({
                "jsonrpc": "2.0", "id": mcp_id, "method": method, "params": params,
            }) + "\n")
            mcp.stdin.flush()
            response = json.loads(mcp.stdout.readline())
            assert response.get("id") == mcp_id and "error" not in response, response
            return response["result"]

        initialized = mcp_request("initialize", {})
        assert initialized["serverInfo"]["name"] == "ctf-rescue"
        listed = mcp_request("tools/list", {})
        assert any(row["name"] == "ctf_inventory" for row in listed["tools"])

        def mcp_call(name: str, arguments: dict[str, object]) -> dict[str, object]:
            result_value = mcp_request(
                "tools/call", {"name": name, "arguments": arguments},
            )
            assert result_value.get("isError") is not True, result_value
            payload = json.loads(result_value["content"][0]["text"])
            assert payload["ok"] is True, payload
            return payload["result"]

        assert mcp_call("ctf_inventory", {})["actual_image_id"]
        mcp_shell = mcp_call("ctf_session_open", {
            "kind": "shell", "name": "mcp-shell",
            "argv": ["/bin/bash", "--noprofile", "--norc"],
        })
        mcp_session_id = str(mcp_shell["session_id"])
        mcp_call("ctf_session_send", {
            "session_id": mcp_session_id, "text": "printf 'MCP_SESSION_OK\\n'",
        })
        mcp_output = mcp_call("ctf_session_read", {
            "session_id": mcp_session_id, "cursor": 0,
            "max_bytes": 32768, "wait_seconds": 2,
        })
        assert "MCP_SESSION_OK" in str(mcp_output["stdout"])
        mcp_call("ctf_session_close", {"session_id": mcp_session_id})
        mcp_call("ctf_progress_record", {"payload": {
            "event": "NEXT_ACTION_SET", "next_action": "continue deterministic smoke",
        }})
        mcp_call("ctf_task_create", {"payload": {
            "task_id": "mcp-task", "role": "evidence", "objective": "verify MCP result",
            "success_condition": "typed result stored", "kill_condition": "ledger rejects result",
            "maximum_turns": 2, "expected_artifacts": [],
            "allowed_hypothesis_family": "mcp-smoke", "forbidden_repeated_paths": [],
        }})
        mcp_call("ctf_task_result", {"payload": {
            "task_id": "mcp-task", "status": "INCONCLUSIVE", "summary": "transport works",
            "command_receipt_ids": [], "session_observation_receipt_ids": [],
            "artifacts": [], "evidence": [], "recommended_next_action": "continue smoke",
        }})
        source = backend.knowledge_source_record({
            "query": "MCP smoke", "tool": "WebSearch", "source_title": "fixture",
            "source_url_or_resource_id": "https://example.test/mcp",
            "bounded_excerpt": "candidate fact", "content_digest": "1" * 64,
            "session_id": "fixture-session", "subagent_id": "",
        })
        mcp_call("ctf_knowledge_hint_record", {"payload": {
            "query": "MCP smoke", "source_receipt_ids": [source["receipt_id"]],
            "atomic_attack_facts": ["candidate fact"],
            "applicability_conditions": ["fixture"],
            "current_challenge_matches": ["fixture"],
            "proposed_attack_path": "run the smoke probe",
            "decisive_experiment": {
                "argv_or_session_plan": {"argv": ["python3", "probe.py"]},
                "success_condition": "probe succeeds", "kill_condition": "probe fails",
            },
            "status": "CANDIDATE",
        }})
        mcp.stdin.close()
        assert mcp.wait(timeout=20) == 0, mcp.stderr.read() if mcp.stderr else ""

        manager = RescueSessionManager(rescue_case.run, root, metadata, packet)
        shell = manager.open(
            kind="shell", name="main-shell", argv=["/bin/bash", "--noprofile", "--norc"],
        )
        manager.send(str(shell["session_id"]), b"printf 'SHELL_OK\\n'\n", encoding="text")
        shell_output = manager.read(str(shell["session_id"]), cursor=0, wait_seconds=2)
        assert "SHELL_OK" in str(shell_output["stdout"])
        manager.close(str(shell["session_id"]))

        gdb = manager.open(kind="gdb", name="smoke-gdb", argv=["gdb", "-q", "/bin/true"])
        manager.send(str(gdb["session_id"]), b"info files\n", encoding="text")
        gdb_output = manager.read(str(gdb["session_id"]), cursor=0, wait_seconds=2)
        assert "Symbols from" in str(gdb_output["stdout"])
        manager.close(str(gdb["session_id"]))

        repl = manager.open(kind="repl", name="python-repl", argv=["python3", "-q"])
        manager.send(str(repl["session_id"]), b"print(6*7)\n", encoding="text")
        repl_output = manager.read(str(repl["session_id"]), cursor=0, wait_seconds=2)
        assert "42" in str(repl_output["stdout"])
        manager.close(str(repl["session_id"]))

        artifact = root / "artifacts" / "solve.py"
        _write(artifact, "#!/usr/bin/env python3\nprint('deterministic smoke exploit')\n")
        artifact.chmod(0o755)
        tcp = manager.open(kind="tcp", name="remote", target_index=0)
        tcp_id = str(tcp["session_id"])
        manager.send(tcp_id, b"CTF{remote-rescue}\n", encoding="text")
        flag_output = manager.read(tcp_id, cursor=0, wait_seconds=3)
        assert "CTF{remote-rescue}" in str(flag_output["stdout"])
        assert flag_output["network_observation"][0]["observed"] is True
        cursor = int(flag_output["cursor_after"])
        manager.send(tcp_id, b"A\x00B\xff", encoding="hex")
        binary_output = manager.read(tcp_id, cursor=cursor, wait_seconds=3)
        binary_bytes = (
            base64.b64decode(binary_output["stdout_base64"])
            if binary_output["stdout_base64"] else str(binary_output["stdout"]).encode()
        )
        assert binary_bytes == b"A\x00B\xff"
        manager.close(tcp_id)

        udp = execute_sandbox(
            metadata,
            [
                "python3", "-c",
                "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
                "s.settimeout(3);s.sendto(b'UDP_OK',(\"udp-smoke.test\",31338));"
                "print(s.recvfrom(64)[0].decode())",
            ],
            10, session_id=rescue_id, session_role="external-rescue",
            timeout_profile="quick_probe", retain_on_timeout=True,
        )
        assert udp["exit_code"] == 0 and "UDP_OK" in str(udp["stdout"])
        assert udp["network_observation"][1]["observed"] is True
        assert udp["network_observation"][1]["established_after"] is None

        timed = execute_sandbox(
            metadata, ["python3", "-c", "import time; time.sleep(3)"], 1,
            session_id=rescue_id, session_role="external-rescue",
            timeout_profile="quick_probe", retain_on_timeout=True,
        )
        assert timed["timed_out"] is True and timed["container_retained"] is True
        assert subprocess.run(
            ["docker", "inspect", str(metadata["name"])],
            capture_output=True, timeout=20, check=False,
        ).returncode == 0

        marker = root / "work" / "recovery-marker.txt"
        _write(marker, "bind persistence\n")
        stale_shell = manager.open(kind="shell", name="stale-shell", argv=["/bin/bash"])
        subprocess.run(
            ["docker", "rm", "--force", str(metadata["name"])],
            capture_output=True, timeout=30, check=False,
        )
        status = _sandbox_control(backend, "status")
        assert status["runtime_state"] == "MISSING" and status["status"] == "RECOVERABLE"
        recovered = _sandbox_control(backend, "recover")
        assert recovered["status"] == "RUNNING" and recovered["stale_persistent_sessions"] >= 1
        assert marker.read_text() == "bind persistence\n"
        stale_state = json.loads((root / "sessions" / str(stale_shell["session_id"]) / "SESSION_STATE.json").read_text())
        assert stale_state["status"] == "STALE"

        promoted = promote_rescue_flag(
            rescue_case.run, rescue_case.challenge, rescue_id,
            execution_receipt_id=str(flag_output["observation_receipt_id"]),
            candidate="CTF{remote-rescue}", exploit_artifact="artifacts/solve.py",
        )
        protected = json.loads(Path(promoted["receipt"]).read_text())
        assert protected["source_type"] == "CLAUDE_RESCUE"
        assert protected["execution_receipt_id"] == flag_output["observation_receipt_id"]
    finally:
        if mcp is not None and mcp.poll() is None:
            if mcp.stdin is not None and not mcp.stdin.closed:
                mcp.stdin.close()
            try:
                mcp.wait(timeout=5)
            except subprocess.TimeoutExpired:
                mcp.terminate()
                try:
                    mcp.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    mcp.kill(); mcp.wait(timeout=5)
        if result is not None:
            root = _rescue_root(rescue_case, result)
            current_metadata = root / "sandbox.json"
            if current_metadata.is_file():
                try:
                    cleanup_sandbox(
                        json.loads(current_metadata.read_text()),
                        session_id=str(result["rescue_attempt_id"]),
                        session_role="external-rescue",
                    )
                except Exception:
                    if metadata is not None:
                        subprocess.run(
                            ["docker", "rm", "--force", str(metadata.get("name") or "")],
                            capture_output=True, timeout=30, check=False,
                        )
        subprocess.run(
            ["docker", "rm", "--force", target_name],
            capture_output=True, timeout=30, check=False,
        )
