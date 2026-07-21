from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
from dataclasses import replace
from types import SimpleNamespace

import pytest

from ctf_os.agent_tools.__main__ import build_parser
from ctf_os.contest import ChallengeSpec, ContestManifest
from ctf_os.rescue import (
    RescueError,
    calculate_packet_digest,
    canonical_json,
    close_rescue,
    load_rescue_ledger,
    prepare_rescue,
    rescue_attempt_id,
    show_rescue,
    validate_exact_live_mutable_run,
    validate_rescue_return,
)
from ctf_os.rescue_tool import (
    _import_input, _input_files, _reject_model_command, _safe_relative,
)
from ctf_os.sandbox.network import ResolvedTarget, Target
from ctf_os.sandbox.preparation import (
    PreparedSandbox,
    RESCUE_SERVICE_ERROR,
    prepare_sandbox_spec,
)
from ctf_os.sandbox.runtime import SandboxSpec, build_run_argv
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
def rescue_case(tmp_path: Path) -> SimpleNamespace:
    repo = tmp_path / "repo"
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
        repo=repo, manifest=manifest, challenge=challenge, workspace=workspace,
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
        session_role="external",
        category="pwn",
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
    return case.run / "rescue" / str(result["rescue_attempt_id"])


def test_prepare_without_intake_triage_and_session_input_adapter(rescue_case: SimpleNamespace) -> None:
    rescue_case.record["input_source"] = "session-input"
    result = _prepare(rescue_case)
    root = _rescue_root(rescue_case, result)
    assert root.parent.parent == rescue_case.run
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
        "CLAUDE_RETURN.json", "CODEX-RESUME.md", "ctf-tool", "sandbox.json",
        ".claude", "context", "work", "evidence", "artifacts", "logs",
    }
    assert expected.issubset({path.name for path in root.iterdir()})
    assert "claude --model sonnet" in result["start_command"]
    assert result["observed_lead_model"] is None
    assert (root / "RESCUE_PACKET.json").stat().st_mode & 0o222 == 0
    assert (rescue_case.run / "STATE.json").read_bytes() == before_state
    assert not (rescue_case.run / "RACE_LINEAGE.jsonl").exists()
    assert before_lineage == b""


def test_deep_requested_model_and_manual_fallback(rescue_case: SimpleNamespace) -> None:
    result = _prepare(
        rescue_case, profile="deep", mode="FRESH_REINTERPRETATION",
        operation_id="deep-op-1",
    )
    root = _rescue_root(rescue_case, result)
    assert "claude --model claude-fable-5" in result["start_command"]
    assert "claude --model opus" in result["fallback_command"]
    assert result["observed_lead_model"] is None
    start = (root / "START.md").read_text()
    assert "--dangerously-skip-permissions" not in start
    assert "manual alternative" in start


def test_subagent_frontmatter_and_model_limits(rescue_case: SimpleNamespace) -> None:
    root = _rescue_root(rescue_case, _prepare(rescue_case))
    expected = {
        "ctf-recon-haiku.md": ("haiku", 6),
        "clean-room-recon-haiku.md": ("haiku", 7),
        "evidence-triage-haiku.md": ("haiku", 5),
        "exploit-builder-sonnet.md": ("sonnet", 12),
        "alternate-solver-sonnet.md": ("sonnet", 10),
    }
    for name, (model, turns) in expected.items():
        text = (root / ".claude" / "agents" / name).read_text()
        for field in ("name:", "description:", "model:", "tools:", "disallowedTools:", "maxTurns:"):
            assert field in text
        assert f"model: {model}" in text
        assert f"maxTurns: {turns}" in text


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
        {"receipt_id": "confirmed", "event_type": "PRIMITIVE_CONFIRMED", "summary": "write primitive", "evidence": ["evidence/primitive.txt"], "artifacts": []},
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
    assert [row["event"] for row in rows] == ["RESCUE_PREPARED", "RESCUE_SANDBOX_READY"]
    shown = show_rescue(rescue_case.run, str(result["rescue_attempt_id"]))
    assert shown["status"] == "READY"
    assert shown["process_state_inferred"] is False
    ledger = rescue_case.run / "rescue" / "RESCUE_LEDGER.jsonl"
    with ledger.open("a", encoding="utf-8") as handle:
        handle.write("not-json\n")
    with pytest.raises(Exception, match="malformed"):
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
            session_id="rescue-service", parent_session_id="sol-main", session_role="external",
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
        session_id="rescue-service", parent_session_id="sol-main", session_role="external",
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


def _remote_flag_result(
    case: SimpleNamespace, root: Path, packet: dict[str, object],
    *, network: bool = True, receipt: bool = True, candidate_in_output: bool = True,
) -> None:
    candidate = "CTF{remote-rescue}"
    artifact = root / "artifacts" / "solve.py"
    _write(artifact, "#!/usr/bin/env python3\n")
    artifact.chmod(0o755)
    evidence = root / "evidence" / "remote.txt"
    _write(evidence, candidate if candidate_in_output else "no flag\n")
    command_path = root / "logs" / "commands.jsonl"
    if receipt:
        _write(command_path, json.dumps({
            "event": "sandbox_exec",
            "command": ["python3", "/artifacts/solve.py", "example.com", "31337"],
            "stdout": candidate if candidate_in_output else "no flag",
            "authorized_network_observed": network,
        }, separators=(",", ":")) + "\n")
    _write_return(
        root, packet, verdict="REMOTE_FLAG_OBTAINED",
        artifacts=[{
            "path": "artifacts/solve.py",
            "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            "executable": True,
        }],
        flag_claim={
            "candidate": candidate, "host": "example.com", "port": 31337,
            "protocol": "tcp",
            "exact_argv": ["python3", "/artifacts/solve.py", "example.com", "31337"],
            "command_evidence": "logs/commands.jsonl",
            "output_evidence": "evidence/remote.txt",
            "exploit_artifact": "artifacts/solve.py",
        },
    )


@pytest.mark.parametrize(
    ("receipt", "network", "candidate_in_output", "message"),
    [
        (False, True, True, "command evidence"),
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
    assert "flag-receipt-save" in resume
    assert "--contest demo" in resume


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
        rescue_case.run, str(result["rescue_attempt_id"]), reason="manual",
        sandbox_cleanup=fake_cleanup,
    )
    assert closed["closed"] is True and closed["workspace_preserved"] is True
    assert seen == [(str(result["rescue_attempt_id"]), str(result["rescue_attempt_id"]), "external")]
    assert root.is_dir() and (root / "RESCUE_PACKET.json").is_file()
    assert load_rescue_ledger(rescue_case.run)[-1]["event"] == "RESCUE_CLOSED"


def test_ctf_tool_identity_is_fixed_and_paths_are_safe(rescue_case: SimpleNamespace) -> None:
    result = _prepare(rescue_case)
    root = _rescue_root(rescue_case, result)
    wrapper = (root / "ctf-tool").read_text()
    assert f"--run-id {RUN_ID}" in wrapper
    assert f"--rescue-id {result['rescue_attempt_id']}" in wrapper
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
    with pytest.raises(RescueError, match="model process"):
        _reject_model_command(argv)


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
