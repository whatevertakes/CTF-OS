from __future__ import annotations

import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from ctf_os.challenge_scope import (
    ChallengeScopeError, record_cloud_mutation, remove_challenge_secrets, save_challenge_secret,
    validate_ai_artifact, validate_model_download,
)
from ctf_os.delegation import BranchCandidate, admit_branch, branch_utility
from ctf_os.events import (
    acknowledge_event, insight_packet, publish_event, save_operator_hint, show_events,
)
from ctf_os.oast import create_oast, oast_events, poll_oast
from ctf_os.race import DEFAULT_WIDTH, parse_branch_spec, start_race_plan
from ctf_os.sandbox.network import NetworkPolicyError, parse_remotes, resolve_targets
from ctf_os.sandbox.resources import GIB, admit, race_width
from ctf_os.sandbox.runtime import SandboxSpec, build_run_argv
from ctf_os.service import ServiceActor, ServiceError, ServiceSpec, _lifecycle
import ctf_os.service as service_module
from ctf_os.solve_launch import (
    MAX_OBSERVATION_HINTS, MAX_PRIORITY_FILES, MAX_SOLVE_LAUNCH_BYTES,
    OBSERVATION_HINT_SEMANTICS, build_solve_launch_context, solve_launch_size,
)
from ctf_os.verification import FastFlagError, mark_fully_verified, record_remote_flag


TEMPLATES = Path("ctf_os/resources/delegation-templates.yaml")


def _state(root: Path, challenge_id: str = "challenge", fingerprint: str = "fp") -> None:
    root.mkdir(parents=True)
    (root / "STATE.json").write_text(json.dumps({
        "schema_version": 1, "challenge_id": challenge_id, "input_fingerprint": fingerprint,
        "status": "PREPARED", "branches": [], "flag_candidate": None,
    }))
    (root / "evidence.log").touch()


def test_solve_launch_context_is_bounded_and_hints_are_not_progress() -> None:
    long_text = "관찰-" + "가" * 2_000
    files = [
        {
            "path": f"path-{number}-{long_text}", "size": number,
            "sha256": "a" * 64, "mime": long_text, "kind": long_text,
        }
        for number in range(40)
    ]
    challenge = SimpleNamespace(
        id="stable-id", key="web/large", category="web", name="large", remotes=(),
        description=long_text, hint=None, flag_format="DEMO{...}",
        flag_pattern=r"\ADEMO\{[^}]+\}\Z", input_profile="standard",
    )
    record = {
        "source_fingerprint": "f" * 64,
        "files": files,
        "priority_files": [item["path"] for item in files],
        "important_metadata": {"file_count": len(files), "total_bytes": 123456},
        "runtime": [long_text] * 20,
        "subtype": long_text,
        "initial_attack_surface": [long_text] * 30,
        "recommended_image": long_text,
        "recommended_resource_profile": long_text,
        "service_plan": {
            "kind": "compose", "status": "READY", "safe_to_start": True,
            "review_reasons": [long_text] * 20,
            "services": [
                {
                    "name": f"service-{number}", "image": long_text,
                    "internal_targets": [long_text] * 20,
                    "mapped_ports": [{"target": 8000, "published": 9000, "protocol": "tcp"}] * 20,
                }
                for number in range(20)
            ],
        },
        "contest_triage": {
            "recommendation": {"bucket": "priority", "rank": 1, "label": long_text},
            "reasons": [{"fact_id": str(number), "text": long_text} for number in range(20)],
            "baseline": {
                "difficulty": long_text, "estimated_solve_time": long_text,
                "success_probability": long_text,
            },
            "setup": {"cost": long_text, "requirements": [long_text] * 20},
            "attack_surface_clarity": long_text,
            "recommended_tools": [long_text] * 20,
            "recommended_playbook": {"category": "web", "path": long_text},
        },
    }

    context = build_solve_launch_context(challenge, record)

    assert len(context["priority_files"]) == MAX_PRIORITY_FILES
    assert len(context["observation_hints"]) == MAX_OBSERVATION_HINTS
    assert solve_launch_size(context) <= MAX_SOLVE_LAUNCH_BYTES
    policy = context["execution_policy"]
    assert policy["observation_hint_semantics"] == OBSERVATION_HINT_SEMANTICS
    assert policy["preflight_hints_are_not_confirmed_vulnerabilities"] is True
    rendered = json.dumps(context, sort_keys=True)
    for forbidden in (
        "contest_triage", "triage_available", "triage_recommendation", "difficulty",
        "estimated_solve_time", "success_probability",
    ):
        assert forbidden not in rendered
    assert "primitive" not in context and "finding" not in context


@pytest.mark.parametrize(("tier", "width"), [(1, 2), (2, 3), (3, 4)])
def test_competition_templates_start_required_native_race_width(tmp_path: Path, tier: int, width: int) -> None:
    root = tmp_path / f"tier-{tier}"
    _state(root)
    specs = parse_branch_spec(None, category="rev", tier=tier, template_path=TEMPLATES)
    assert len(specs) == DEFAULT_WIDTH[tier] == width
    board = start_race_plan(
        root, challenge_id="challenge", input_fingerprint="fp", parent_session_id="sol-main",
        category="rev", tier=tier, tier_reason="race", branch_specs=specs,
    )
    assert len(board["active_branches"]) == width
    assert board["sol_lane"]["status"] == "RUNNING"
    assert board["native_children_created"] is False
    assert all(row["prompt_packet"]["input_fingerprint"] == "fp" for row in board["active_branches"])


def test_race_plan_archives_previous_plan_and_exact_duplicate_only(tmp_path: Path) -> None:
    root = tmp_path / "solve"
    _state(root)
    specs = parse_branch_spec(None, category="rev", tier=2, template_path=TEMPLATES)
    start_race_plan(root, challenge_id="challenge", input_fingerprint="fp", parent_session_id="sol-main", category="rev", tier=2, tier_reason="one", branch_specs=specs)
    second = start_race_plan(root, challenge_id="challenge", input_fingerprint="fp", parent_session_id="sol-main", category="rev", tier=2, tier_reason="two", branch_specs=specs)
    archives = list(root.glob("DELEGATION_PLAN.stale-*.json"))
    assert len(archives) == 1
    assert json.loads(archives[0].read_text())["status"] == "STALE"
    assert second["race_id"]
    ledger = [json.loads(line) for line in (root / "RACE_LEDGER.jsonl").read_text().splitlines()]
    assert [row["event"] for row in ledger].count("RACE_PLAN_COMMITTED") == 2


def test_race_plan_recovers_corrupt_ledger_without_bypassing_fingerprint(tmp_path: Path) -> None:
    root = tmp_path / "recover"; _state(root)
    (root / "DELEGATION_PLAN.json").write_text("{broken")
    specs = parse_branch_spec(None, category="rev", tier=2, template_path=TEMPLATES)
    board = start_race_plan(root, challenge_id="challenge", input_fingerprint="fp", parent_session_id="sol-main", category="rev", tier=2, tier_reason="recover", branch_specs=specs)
    assert len(board["active_branches"]) == 3
    assert len(list(root.glob("DELEGATION_PLAN.corrupt-*.txt"))) == 1
    assert any(json.loads(line)["event"] == "CORRUPT_PLAN_RECOVERED" for line in (root / "RACE_LEDGER.jsonl").read_text().splitlines())
    with pytest.raises(Exception, match="fingerprint mismatch"):
        start_race_plan(root, challenge_id="challenge", input_fingerprint="changed", parent_session_id="sol-main", category="rev", tier=2, tier_reason="bad", branch_specs=specs)


def test_event_bus_priority_idempotency_conflicts_packets_and_operator_hints(tmp_path: Path) -> None:
    root = tmp_path / "solve"
    _state(root)
    event = publish_event(
        root, challenge_id="challenge", input_fingerprint="fp", session_id="static",
        event_type="EXPLOIT_PRIMITIVE", priority="LOW", summary="comparison bypass",
        useful_for=["dynamic"], event_id="event-1",
    )
    # Deprecated primitive rows are readable but candidate-grade.
    assert event["priority"] == "LOW"
    with pytest.raises(Exception, match="verified receipt"):
        publish_event(root, challenge_id="challenge", input_fingerprint="fp", session_id="flagger", event_type="REMOTE_FLAG_OBTAINED", summary="flag receipt ready", priority="LOW", event_id="remote-1", useful_for=["flag-verifier"])
    assert publish_event(
        root, challenge_id="challenge", input_fingerprint="fp", session_id="static",
        event_type="EXPLOIT_PRIMITIVE", priority="LOW", summary="comparison bypass",
        useful_for=["dynamic"], event_id="event-1",
    )["idempotent"] is True
    with pytest.raises(Exception, match="conflicting"):
        publish_event(
            root, challenge_id="challenge", input_fingerprint="fp", session_id="static",
            event_type="EXPLOIT_PRIMITIVE", summary="different fact", event_id="event-1",
        )
    publish_event(root, challenge_id="challenge", input_fingerprint="fp", session_id="other", event_type="REJECTED_HYPOTHESIS", summary="comparison bypass does not hold", event_id="event-2", useful_for=["dynamic"])
    assert {row["event_id"] for row in show_events(root, input_fingerprint="fp")} == {"event-1", "event-2"}
    packet = insight_packet(root, input_fingerprint="fp", target_session_id="dynamic")
    assert {row["summary"] for row in packet["events"]} == {"comparison bypass", "comparison bypass does not hold"}
    acknowledge_event(root, event_id="event-1", session_id="dynamic", input_fingerprint="fp")
    assert [row["event_id"] for row in insight_packet(root, input_fingerprint="fp", target_session_id="dynamic")["events"]] == ["event-2"]
    hint = save_operator_hint(
        root, challenge_id="challenge", input_fingerprint="fp", summary="heap path",
        active_branches=[{"session_id": "dynamic", "status": "RUNNING"}, {"session_id": "done", "status": "TERMINATED"}],
        targets=["dynamic", "done"],
    )
    assert hint["recipients"] == ["dynamic"] and hint["ignored_inactive_targets"] == ["done"]


def test_adaptive_utility_replaces_plateau_and_prioritizes_remote_flag() -> None:
    candidate = BranchCandidate.create(
        session_id="b", role="solver", hypothesis_family="family", hypothesis="solve",
        scope=["challenge"], tool_strategy=["python"], expected_artifacts=["artifacts/solve.py"],
    )
    branch = {
        "session_id": candidate.session_id, "role": candidate.role,
        "hypothesis_family": candidate.hypothesis_family, "hypothesis": candidate.hypothesis,
        "scope": list(candidate.scope), "tool_strategy": list(candidate.tool_strategy),
        "expected_artifacts": list(candidate.expected_artifacts), "admission": {"maximum_overlap_score": 0},
        "budget_seconds": 60, "started_at": None,
    }
    plan = {"branches": [branch]}
    blockers = [
        {"session_id": "b", "type": "BLOCKER", "sibling_insight_applied": True}
        for _ in range(3)
    ]
    assert branch_utility(plan, session_id="b", checkpoints=blockers, result=None)["classification"] == "REPLACE_ATTACK_FAMILY"
    flag = [{"session_id": "b", "type": "FLAG_CANDIDATE"}]
    assert branch_utility(plan, session_id="b", checkpoints=flag, result=None)["classification"] == "FLAG_PATH"


def test_network_supports_declared_private_udp_tls_websocket_dns_and_blocks_metadata(monkeypatch) -> None:
    targets = parse_remotes((
        {"host": "10.10.20.15", "port": 31337, "protocol": "udp", "organizer_declared": True},
        "tls://8.8.8.8:443", "websocket://1.1.1.1:80", "dns://9.9.9.9:53",
    ))
    assert [row.protocol for row in targets] == ["udp", "tls", "websocket", "dns"]
    assert targets[0].transport == "udp"
    with pytest.raises(NetworkPolicyError, match="organizer_declared"):
        parse_remotes(("tcp://10.10.20.15:31337",))
    with pytest.raises(NetworkPolicyError, match="metadata"):
        parse_remotes(({"host": "169.254.169.254", "port": 80, "protocol": "http", "organizer_declared": True},))
    with pytest.raises(NetworkPolicyError, match="Docker host gateway"):
        parse_remotes(({"host": "172.17.0.1", "port": 2375, "protocol": "tcp", "organizer_declared": True},))
    monkeypatch.setattr("socket.getaddrinfo", lambda host, port, family, socktype: [(family, socktype, 0, "", (host, port))])
    assert resolve_targets((targets[0],))[0].address == "10.10.20.15"


def test_category_sandboxes_enable_ptrace_forensic_mount_and_never_socket(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "input"; source.mkdir()
    pwn = build_run_argv(SandboxSpec("contest", "id", "pwn", source, tmp_path / "pwn", category="pwn"))
    assert "SYS_PTRACE" in pwn and "seccomp=unconfined" in pwn and "docker.sock" not in " ".join(pwn)
    original_exists = Path.exists
    monkeypatch.setattr(Path, "exists", lambda self: True if str(self) in {"/dev/loop-control", "/dev/loop0"} else original_exists(self))
    forensic = build_run_argv(SandboxSpec("contest", "id", "forensic", source, tmp_path / "forensic", category="forensic"))
    assert "SYS_ADMIN" in forensic and any("/dev/loop-control" in item for item in forensic)
    ai = build_run_argv(SandboxSpec("contest", "id", "ai", source, tmp_path / "ai", category="ai", gpu_enabled=True))
    assert ai[ai.index("--gpus") + 1] == "all"


def test_branch_private_service_child_lifecycle_is_scoped(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "input"; source.mkdir()
    private = ServiceSpec("contest", "id", source, tmp_path, {"kind": "dockerfile"}, branch_id="worker-1")
    shared = ServiceSpec("contest", "id", source, tmp_path, {"kind": "dockerfile"})
    actor = ServiceActor("worker-1", role="child", parent_session_id="sol-main")
    monkeypatch.setattr("ctf_os.service._claim_ownership", lambda *args: None)
    monkeypatch.setattr("ctf_os.service._update_ownership", lambda *args: {})
    with _lifecycle(private, actor, "restart", lambda argv, timeout: subprocess.CompletedProcess(argv, 0, "", ""), "docker"):
        pass
    with pytest.raises(ServiceError, match="DENIED_SERVICE_LIFECYCLE"):
        with _lifecycle(shared, actor, "restart", lambda argv, timeout: subprocess.CompletedProcess(argv, 0, "", ""), "docker"):
            pass


def test_branch_private_reset_recreates_only_own_service(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "input"; source.mkdir()
    spec = ServiceSpec("contest", "id", source, tmp_path, {"kind": "dockerfile"}, branch_id="worker-1")
    actor = ServiceActor("worker-1", role="child", parent_session_id="sol-main")
    calls = []
    monkeypatch.setattr(service_module, "service_cleanup", lambda *args, **kwargs: calls.append("cleanup") or {})
    monkeypatch.setattr(service_module, "service_build", lambda *args, **kwargs: calls.append("build") or {})
    monkeypatch.setattr(service_module, "service_start", lambda *args, **kwargs: calls.append("start") or {})
    result = service_module.service_reset(spec, actor=actor)
    assert calls == ["cleanup", "build", "start"] and result["reset"] is True


def test_total_budget_allows_multiple_heavy_and_shrinks_width(monkeypatch) -> None:
    status = {
        "active": [], "reserved_memory_bytes": 0, "admission_memory_budget_bytes": 28 * GIB,
        "reserved_cpus": 0.0, "admission_cpu_budget": 10.0,
    }
    monkeypatch.setattr("ctf_os.sandbox.resources.sandbox_status", lambda **kwargs: status)
    assert admit("heavy") is status
    fitted = race_width(3, profile_names=["heavy", "heavy", "light"])
    assert fitted["admitted_width"] == 2 and fitted["shrink_required"] is True


def test_oast_redacts_and_is_challenge_isolated(tmp_path: Path) -> None:
    root = tmp_path / "solve"; _state(root)
    record = create_oast(root, challenge_id="challenge", input_fingerprint="fp", branch_id="web", provider_base="https://oast.example")
    payload = json.dumps({"events": [{
        "method": "POST", "headers": {"Cookie": "secret", "User-Agent": "bot"},
        "body": "token=secret", "source": "203.0.113.1",
    }]}).encode()
    result = poll_oast(root, oast_id=record["oast_id"], input_fingerprint="fp", fetch=lambda url: payload)
    assert result["new_event_count"] == 1
    event = oast_events(root, oast_id=record["oast_id"], input_fingerprint="fp")[0]
    assert "cookie" not in event["headers"] and "[TOKEN_REDACTED]" in event["body"]
    with pytest.raises(Exception, match="different challenge"):
        oast_events(root, oast_id=record["oast_id"], input_fingerprint="other")


def test_challenge_credentials_cloud_mutation_and_ai_guard(tmp_path: Path) -> None:
    worker = tmp_path / "workers" / "cloud-1"; worker.mkdir(parents=True)
    secret = save_challenge_secret(worker, branch_id="cloud-1", name="token", value="abc", provenance="challenge-provided", challenge_id="c")
    assert secret["value"] == "[REDACTED]" and Path(secret["path"]).stat().st_mode & 0o777 == 0o600
    with pytest.raises(ChallengeScopeError, match="personal"):
        save_challenge_secret(worker, branch_id="cloud-1", name="bad", value="abc", provenance="personal", challenge_id="c")
    mutation = record_cloud_mutation(worker, challenge_id="c", branch_id="cloud-1", account_scope="tenant-ctf", declared_scopes=["tenant-ctf"], action="create role binding", resource="challenge/ns", result="ok")
    assert mutation["account_scope"] == "tenant-ctf"
    with pytest.raises(ChallengeScopeError, match="outside"):
        record_cloud_mutation(worker, challenge_id="c", branch_id="cloud-1", account_scope="personal", declared_scopes=["tenant-ctf"], action="list", resource="x", result="x")
    model = tmp_path / "model.pkl"; model.write_bytes(b"unsafe")
    with pytest.raises(ChallengeScopeError, match="sandbox"):
        validate_ai_artifact(model, inside_sandbox=False)
    assert validate_ai_artifact(model, inside_sandbox=True)["sandbox_required"] is True
    assert validate_model_download(
        "https://models.example/challenge/model.safetensors",
        allowed_domains=["models.example"], expected_size_bytes=1024,
    )["sandbox_download_required"] is True
    with pytest.raises(ChallengeScopeError, match="allowlist"):
        validate_model_download(
            "https://unrelated.example/model.bin",
            allowed_domains=["models.example"], expected_size_bytes=1024,
        )
    assert remove_challenge_secrets(worker)["removed"] == ["token"]


def test_remote_flag_fast_path_and_full_verification_are_separate(tmp_path: Path) -> None:
    root = tmp_path / "solve"; _state(root)
    exploit = root / "exploit" / "solve.py"; exploit.parent.mkdir(); exploit.write_text("print('flag')")
    targets = parse_remotes(("tcp://8.8.8.8:31337",))
    result = record_remote_flag(
        root, challenge_id="challenge", input_fingerprint="fp", branch_id="dynamic",
        declared_targets=targets, observed_host="8.8.8.8", observed_port=31337,
        observed_protocol="tcp", network_observed=True, output="win CTF{first_flag}",
        candidate="CTF{first_flag}", flag_pattern=r"\ACTF\{[^}]+\}\Z",
        command_argv=["python3", "/artifacts/exploit/solve.py"], exploit_artifact="exploit/solve.py",
    )
    assert result["state"] == "SUBMISSION_RECOMMENDED"
    assert result["full_clean_replay_required_before_human_submission"] is False
    assert result["automatic_submission_attempted"] is False
    assert json.loads((root / "STATE.json").read_text())["status"] == "SUBMISSION_RECOMMENDED"
    assert mark_fully_verified(root, input_fingerprint="fp")["state"] == "FULLY_VERIFIED"
    with pytest.raises(FastFlagError, match="declared target"):
        record_remote_flag(
            root, challenge_id="challenge", input_fingerprint="fp", branch_id="dynamic",
            declared_targets=targets, observed_host="1.1.1.1", observed_port=31337,
            observed_protocol="tcp", network_observed=True, output="CTF{x}", candidate="CTF{x}",
            flag_pattern=r"\ACTF\{[^}]+\}\Z", command_argv=["python3", "solve.py"],
            exploit_artifact="exploit/solve.py",
        )


def test_placeholder_remote_candidate_stays_low_confidence(tmp_path: Path) -> None:
    root = tmp_path / "placeholder"; _state(root)
    exploit = root / "exploit" / "solve.py"; exploit.parent.mkdir(); exploit.write_text("print('x')")
    result = record_remote_flag(
        root, challenge_id="challenge", input_fingerprint="fp", branch_id="b",
        declared_targets=parse_remotes(("tcp://8.8.8.8:31337",)), observed_host="8.8.8.8",
        observed_port=31337, observed_protocol="tcp", network_observed=True,
        output="CTF{example}", candidate="CTF{example}", flag_pattern=r"\ACTF\{[^}]+\}\Z",
        command_argv=["python3", "solve.py"], exploit_artifact="exploit/solve.py",
    )
    assert result["state"] == "FLAG_CANDIDATE" and result["confidence"] == "LOW"
    assert result["branch_actions"]["stop_low_value_branches"] is False


def test_rev_tier2_end_to_end_first_to_flag_simulation(tmp_path: Path) -> None:
    root = tmp_path / "rev"; _state(root, "rev-tnt", "rev-fp")
    specs = parse_branch_spec(None, category="rev", tier=2, template_path=TEMPLATES)
    board = start_race_plan(root, challenge_id="rev-tnt", input_fingerprint="rev-fp", parent_session_id="sol-main", category="rev", tier=2, tier_reason="normal rev", branch_specs=specs)
    static, dynamic, independent = [row["session_id"] for row in board["active_branches"]]
    publish_event(root, challenge_id="rev-tnt", input_fingerprint="rev-fp", session_id=static, event_type="SUPPORTED_FACT", summary="comparison checks 32 bytes", useful_for=[dynamic, independent])
    publish_event(root, challenge_id="rev-tnt", input_fingerprint="rev-fp", session_id=dynamic, event_type="EXPLOIT_PRIMITIVE", summary="oracle leaks one byte", useful_for=[independent])
    assert len(insight_packet(root, input_fingerprint="rev-fp", target_session_id=independent)["events"]) == 2
    artifact = root / "exploit" / "solve.py"; artifact.parent.mkdir(); artifact.write_text("print('CTF{race_won}')")
    publish_event(root, challenge_id="rev-tnt", input_fingerprint="rev-fp", session_id=independent, event_type="ARTIFACT_READY", summary="solver ready", artifacts=["exploit/solve.py"])
    flag = record_remote_flag(
        root, challenge_id="rev-tnt", input_fingerprint="rev-fp", branch_id=independent,
        declared_targets=parse_remotes(("tls://8.8.8.8:443",)), observed_host="8.8.8.8",
        observed_port=443, observed_protocol="tls", network_observed=True,
        output="CTF{race_won}", candidate="CTF{race_won}", flag_pattern=r"\ACTF\{[^}]+\}\Z",
        command_argv=["python3", "/artifacts/exploit/solve.py"], exploit_artifact="exploit/solve.py",
    )
    assert flag["state"] == "SUBMISSION_RECOMMENDED"
    assert flag["branch_actions"] == {"prioritize": independent, "stop_low_value_branches": True, "maximum_verifiers_to_keep": 1}


def test_pwn_tier3_crash_private_restart_and_remote_flag_simulation(tmp_path: Path) -> None:
    root = tmp_path / "pwn"; _state(root, "pwn-race", "pwn-fp")
    specs = parse_branch_spec(None, category="pwn", tier=3, template_path=TEMPLATES)
    board = start_race_plan(root, challenge_id="pwn-race", input_fingerprint="pwn-fp", parent_session_id="sol-main", category="pwn", tier=3, tier_reason="hard pwn", branch_specs=specs)
    assert [row["role"] for row in board["active_branches"]] == [
        "input-control-to-poc", "runtime-primitive-to-poc", "independent-full-solve", "alternate-exploit-mechanism",
    ]
    dynamic = board["active_branches"][1]["session_id"]
    crash = publish_event(root, challenge_id="pwn-race", input_fingerprint="pwn-fp", session_id=dynamic, event_type="SERVICE_CRASHED", summary="heap assertion", recommended_action="restart branch-private service")
    private = ServiceSpec("contest", "pwn-race", root, root, {"kind": "dockerfile"}, branch_id=dynamic)
    assert crash["type"] == "SERVICE_CRASHED" and private.stable_alias == "branch-service" and private.branch_id == dynamic
    exploit = root / "exploit" / "solve.py"; exploit.parent.mkdir(); exploit.write_text("print('PWN{won}')")
    result = record_remote_flag(
        root, challenge_id="pwn-race", input_fingerprint="pwn-fp", branch_id=dynamic,
        declared_targets=parse_remotes(("tcp://8.8.4.4:31337",)), observed_host="8.8.4.4",
        observed_port=31337, observed_protocol="tcp", network_observed=True,
        output="PWN{won}", candidate="PWN{won}", flag_pattern=r"\APWN\{[^}]+\}\Z",
        command_argv=["python3", "/artifacts/exploit/solve.py"], exploit_artifact="exploit/solve.py",
    )
    assert result["state"] == "SUBMISSION_RECOMMENDED"


def test_web_oast_tier2_blind_callback_simulation(tmp_path: Path) -> None:
    root = tmp_path / "web"; _state(root, "web-blind", "web-fp")
    specs = parse_branch_spec(None, category="web", tier=2, template_path=TEMPLATES)
    board = start_race_plan(root, challenge_id="web-blind", input_fingerprint="web-fp", parent_session_id="sol-main", category="web", tier=2, tier_reason="blind path", branch_specs=specs)
    assert [row["role"] for row in board["active_branches"]] == ["reachable-sink-to-exploit", "highest-value-payload-test", "independent-exploit-chain"]
    branch = board["active_branches"][1]["session_id"]
    oast = create_oast(root, challenge_id="web-blind", input_fingerprint="web-fp", branch_id=branch, provider_base="https://oast.example")
    callback = json.dumps({"events": [{"method": "GET", "source": "bot", "headers": {}, "body": "blind SSRF hit"}]}).encode()
    assert poll_oast(root, oast_id=oast["oast_id"], input_fingerprint="web-fp", fetch=lambda url: callback)["new_event_count"] == 1
    fact = publish_event(root, challenge_id="web-blind", input_fingerprint="web-fp", session_id=branch, event_type="SUPPORTED_FACT", summary="OAST callback confirms blind SSRF")
    assert fact["type"] == "SUPPORTED_FACT"


def test_cloud_tier2_scoped_credential_iam_mutation_flag_simulation(tmp_path: Path) -> None:
    root = tmp_path / "cloud"; _state(root, "cloud-iam", "cloud-fp")
    specs = parse_branch_spec(None, category="cloud", tier=2, template_path=TEMPLATES)
    board = start_race_plan(root, challenge_id="cloud-iam", input_fingerprint="cloud-fp", parent_session_id="sol-main", category="cloud", tier=2, tier_reason="iam path", branch_specs=specs)
    assert [row["role"] for row in board["active_branches"]] == ["scoped-chain-to-exploit", "highest-value-api-test", "exploit-path-implementation"]
    branch = board["active_branches"][2]["session_id"]
    worker = root / "workers" / branch; worker.mkdir(parents=True)
    save_challenge_secret(worker, branch_id=branch, name="temporary-token", value="scoped", provenance="challenge-provided", challenge_id="cloud-iam")
    mutation = record_cloud_mutation(worker, challenge_id="cloud-iam", branch_id=branch, account_scope="project-ctf", declared_scopes=["project-ctf"], action="bind challenge role", resource="projects/project-ctf/roles/flag", result="success")
    assert mutation["event_id"]
    exploit = root / "exploit" / "cloud.py"; exploit.parent.mkdir(); exploit.write_text("print('CLOUD{iam_path}')")
    flag = record_remote_flag(
        root, challenge_id="cloud-iam", input_fingerprint="cloud-fp", branch_id=branch,
        declared_targets=parse_remotes(("https://8.8.8.8:443",)), observed_host="8.8.8.8",
        observed_port=443, observed_protocol="https", network_observed=True,
        output="CLOUD{iam_path}", candidate="CLOUD{iam_path}", flag_pattern=r"\ACLOUD\{[^}]+\}\Z",
        command_argv=["python3", "/artifacts/exploit/cloud.py"], exploit_artifact="exploit/cloud.py",
    )
    assert flag["state"] == "SUBMISSION_RECOMMENDED"
