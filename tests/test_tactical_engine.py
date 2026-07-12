from __future__ import annotations

from collections import deque
from dataclasses import asdict
import json
from pathlib import Path

from ctf_os.local_state import CURRENT_SCHEMA_VERSION, LocalState
from ctf_os.models import Challenge, ChallengeSession, ContractTask, ContractTaskStatus, Event
from ctf_os.application import LocalApplication
from ctf_os.config import AppConfig, default_config_mapping
from ctf_os.contest_parser import ContestManifest
from ctf_os.intake import IntakeChallenge
from ctf_os.solver_engine.loop_detector import LoopDetector, ProgressSnapshot
from ctf_os.tactical_engine.planners import default_planner_registry
from ctf_os.tactical_engine.profiles import ProblemClassifier
from ctf_os.tactical_engine.rules import LocalSchedulerRuleState, ReplanEngine, RuleParser
from ctf_os.tactical_engine.strategies import StrategyExecutor, default_strategy_registry
from benchmarks.run import ChallengeResult, _load, _report


def test_acceptance_a_strategy_changes_bootstrap_tools_artifacts_and_budget(tmp_path: Path) -> None:
    executor = StrategyExecutor()
    fake_which = lambda name: f"/tools/{name}"
    results = {
        strategy: executor.bootstrap(strategy, tmp_path / strategy, which=fake_which)
        for strategy in ("fast_recon", "dynamic_analysis", "symbolic_math")
    }
    manifests = {key: json.loads(value.manifest_path.read_text()) for key, value in results.items()}
    assert {item["profile"] for item in manifests.values()} == {"base", "pwn", "crypto"}
    assert manifests["fast_recon"]["commands"] != manifests["dynamic_analysis"]["commands"]
    assert manifests["dynamic_analysis"]["tools"] != manifests["symbolic_math"]["tools"]
    assert manifests["fast_recon"]["artifacts"] != manifests["symbolic_math"]["artifacts"]
    assert {item["budget"]["timeout_sec"] for item in manifests.values()} == {300, 900, 1200}
    assert all(value.launch_script.is_file() and value.replay_script.is_file() for value in results.values())


def test_capability_preflight_records_missing_and_selects_fallback(tmp_path: Path) -> None:
    result = StrategyExecutor().bootstrap("mobile_analysis", tmp_path, which=lambda _: None)
    manifest = json.loads(result.manifest_path.read_text())
    assert result.degraded
    assert result.fallback_strategy == "artifact_recovery"
    assert set(manifest["missing_required"]) == {"jadx", "apktool"}


def test_profile_planner_strategy_contract_flows_for_required_subtypes() -> None:
    classifier = ProblemClassifier()
    registry = default_planner_registry()
    cases = (
        ("pwn", "glibc heap tcache fastbin x86_64", "heap.glibc", "exploit_build"),
        ("pwn", "printf format string %p %n", "format_string", "dynamic_analysis"),
        ("web", "SSRF url parameter internal endpoint", "ssrf", "protocol_replay"),
        ("web", "request smuggling CL.TE response desync", "request_smuggling", "protocol_replay"),
        ("web", "JWT jwks jku algorithm", "jwt", "protocol_replay"),
        ("mobile", "Android APK manifest", "android_static", "mobile_analysis"),
        ("cloud", "Terraform AWS IAM policy", "configuration", "cloud_analysis"),
    )
    for category, evidence, subtype, strategy in cases:
        profile = classifier.classify(category, (evidence,))
        plan = registry.plan(profile)
        assert profile.subtype == subtype
        assert not plan.fallback_used
        assert strategy in {contract.strategy for contract in plan.contracts}
        assert all(contract.commands and contract.success_signals and contract.transition_conditions for contract in plan.contracts)


def test_planner_coverage_and_visible_unknown_fallback() -> None:
    registry = default_planner_registry()
    required = {
        "pwn.heap.glibc", "pwn.format_string", "web.ssrf", "web.request_smuggling",
        "web.jwt", "mobile.android_static", "cloud.configuration",
    }
    assert required <= set(registry.registered())
    assert len(registry.registered()) >= 60
    unknown = ProblemClassifier().classify("web", ("featureless service",))
    plan = registry.plan(unknown)
    assert unknown.subtype == "unknown"
    assert plan.fallback_used and plan.planner_id == "generic.unknown"


def test_acceptance_b_libc_leak_cancels_recon_spawns_exploit_and_is_idempotent(tmp_path: Path) -> None:
    state = LocalState(tmp_path / "state.db")
    challenge = state.upsert_challenge(Challenge("Demo", "pwn", "heap"))
    session = state.upsert_challenge_session(ChallengeSession(challenge.id, "gpt-5.6-sol"))
    recon = state.upsert_contract_task(ContractTask(
        session.id, challenge.id, "recon-a", "recon", "low priority recon",
        tool_strategy="fast_recon", priority=10,
    ))
    profile = ProblemClassifier().classify("pwn", ("glibc heap tcache",))
    state.upsert_problem_profile(challenge.id, asdict(profile))
    rule = RuleParser().parse({
        "schema_version": 1, "id": "switch-after-libc-leak", "priority": 90,
        "when": {"all": [
            {"event": "finding.created", "field": "finding.kind", "op": "eq", "value": "libc_leak"},
            {"field": "finding.confidence", "op": "gte", "value": 0.8},
        ]},
        "actions": [
            {"type": "cancel_contracts", "selector": {"tags_any": ["recon"]}},
            {"type": "promote_artifact", "artifact_type": "libc_base"},
            {"type": "spawn_plan", "planner": "pwn.heap.exploitation"},
        ], "cooldown_seconds": 30, "max_fires": 1,
    })
    engine = ReplanEngine((rule,))
    event = {"id": "finding-1", "type": "finding.created", "finding": {"kind": "libc_leak", "confidence": .95}}
    first = engine.evaluate(event, LocalSchedulerRuleState(state, challenge.id))
    second = engine.evaluate(event, LocalSchedulerRuleState(state, challenge.id))
    assert first[0].matched and not second[0].matched
    assert state.get_contract_task(recon.id).status is ContractTaskStatus.CANCELLED
    tasks = state.list_contract_tasks(session.id)
    assert sum(item.tool_strategy == "exploit_build" for item in tasks) == 1


def test_application_evaluates_rule_in_current_tick_and_audits_snapshots(tmp_path: Path) -> None:
    raw = default_config_mapping("Demo", team_id="team", member_name="member")
    config = AppConfig(raw, tmp_path / "config.yaml")
    config.validate()
    state = LocalState(tmp_path / "state.db")
    challenge = state.upsert_challenge(Challenge("Demo", "pwn", "heap-live"))
    rule = {
        "schema_version": 1, "id": "live-libc", "priority": 90,
        "when": {"event": "finding.created", "field": "finding.kind", "op": "eq", "value": "libc_leak"},
        "actions": [
            {"type": "cancel_contracts", "selector": {"tags_any": ["recon"]}},
            {"type": "spawn_plan", "planner": "pwn.heap.exploitation"},
        ], "max_fires": 1,
    }
    session = state.upsert_challenge_session(ChallengeSession(
        challenge.id, "gpt-5.6-sol", execution_contract={"replan_when": [rule], "escalate_when": []},
    ))
    recon = state.upsert_contract_task(ContractTask(
        session.id, challenge.id, "recon", "recon", "continue recon", tool_strategy="fast_recon",
    ))
    state.upsert_problem_profile(challenge.id, asdict(ProblemClassifier().classify("pwn", ("glibc heap tcache",))))
    event = Event("team", "member", "Demo", "FINDING", challenge_id=challenge.id,
                  message="confirmed libc leak", payload={"finding_kind": "libc_leak", "confidence": .95})
    state.append_event(event)
    LocalApplication(config)._evaluate_replanning(state, challenge, event)

    assert state.get_contract_task(recon.id).status is ContractTaskStatus.CANCELLED
    assert sum(item.tool_strategy == "exploit_build" for item in state.list_contract_tasks(session.id)) == 1
    audit = [item for item in state.list_events(challenge_id=challenge.id) if item.type.startswith("rule.")]
    assert [item.type for item in audit] == ["rule.matched", "rule.executed"]
    assert "before" in audit[-1].payload and "after" in audit[-1].payload


def test_duplicate_rule_spawn_queue_materializes_one_scheduler_attempt(tmp_path: Path) -> None:
    raw = default_config_mapping("Demo", team_id="team", member_name="member")
    raw["paths"] = {"incoming": str(tmp_path / "incoming"),
                    "output": str(tmp_path / "output" / "team" / "member")}
    config = AppConfig(raw, tmp_path / "config.yaml")
    config.validate()
    state = LocalState(config.state_path())
    challenge = state.upsert_challenge(Challenge("Demo", "pwn", "heap-duplicate"))
    session = state.upsert_challenge_session(ChallengeSession(challenge.id, "gpt-5.6-sol"))
    durable = state.upsert_contract_task(ContractTask(
        session.id, challenge.id, "semantic-exploit", "exploit", "consume promoted leak",
        tool_strategy="exploit_build",
    ))
    manifest_path = tmp_path / "incoming" / "Demo" / "contest.md"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text("# fixture\n", encoding="utf-8")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    intake = (IntakeChallenge(
        ContestManifest("Demo", manifest_path, (challenge,)), challenge, workspace, (),
    ),)
    app = LocalApplication(config)
    app._rule_created_task_ids.extend(((challenge.id, durable.id), (challenge.id, durable.id)))
    plans = deque()

    assert app._drain_rule_spawn_requests(plans, intake)
    assert len(plans) == 1
    assert plans[0].contract_task_id == durable.id


def test_semantic_loop_clusters_paraphrase_and_address_only_crashes() -> None:
    detector = LoopDetector(repeat_threshold=2)
    assert not detector.observe_snapshot(ProgressSnapshot(attempt_id="a", output="server connection refused during handshake", failure_class="network", hypothesis="H")).loop
    paraphrase = detector.observe_snapshot(ProgressSnapshot(attempt_id="b", output="connection was refused by server", failure_class="network", hypothesis="H"))
    assert paraphrase.loop and paraphrase.cluster

    crashes = LoopDetector(repeat_threshold=2)
    crashes.observe_snapshot(ProgressSnapshot(output="SIGSEGV at 0x7fff12345678 in parser", crash_signature="SIGSEGV at 0x7fff12345678 in parser", hypothesis="overflow"))
    repeated = crashes.observe_snapshot(ProgressSnapshot(output="SIGSEGV at 0x5555abcdef00 in parser", crash_signature="SIGSEGV at 0x5555abcdef00 in parser", hypothesis="overflow"))
    assert repeated.loop


def test_acceptance_c_changed_input_or_artifact_is_not_loop_and_progress_releases_plateau() -> None:
    detector = LoopDetector(repeat_threshold=2)
    detector.observe_snapshot(ProgressSnapshot(command="fuzz target", input_hash="seed-a", artifact_hash="bin-a", hypothesis="parser"))
    changed_input = detector.observe_snapshot(ProgressSnapshot(command="fuzz target", input_hash="seed-b", artifact_hash="bin-a", coverage_delta=1, hypothesis="parser"))
    changed_artifact = detector.observe_snapshot(ProgressSnapshot(command="fuzz target", input_hash="seed-b", artifact_hash="bin-b", hypothesis="parser"))
    leak = detector.observe_snapshot(ProgressSnapshot(command="fuzz target", input_hash="seed-b", artifact_hash="bin-b", new_leaks=1, hypothesis="parser"))
    assert not changed_input.loop and not changed_input.plateau
    assert not changed_artifact.loop and not changed_artifact.plateau
    assert not leak.loop and leak.progress_delta > 0


def test_schema_v10_contains_tactical_tables(tmp_path: Path) -> None:
    state = LocalState(tmp_path / "state.db")
    assert CURRENT_SCHEMA_VERSION == 10
    with state._connect() as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"problem_profiles", "tactical_artifacts", "replan_rule_fires"} <= tables


def test_benchmark_manifest_and_report_schema_cover_twelve_challenges() -> None:
    manifests = _load()
    assert len(manifests) >= 12
    assert {item["category"] for item in manifests} >= {
        "pwn", "web", "crypto", "rev", "forensics", "misc", "password", "mobile", "cloud",
    }
    result = ChallengeResult("fixture", "misc", "protocol", "solved", "protocol_replay",
                             "misc.protocol", .1, True, None, tool_calls=2,
                             artifact_handoff_count=1, artifact_handoff_success=1, timeline=[])
    report = _report([result], mode="smoke", seed=7)
    assert report["schema_version"] == 1
    assert report["summary"] == {
        "challenges": 1, "attempted": 1, "solved": 1, "solve_rate": 1.0,
        "valid_flag_rate": 1.0, "tool_calls": 2,
        "artifact_handoff_count": 1, "artifact_handoff_success": 1,
    }
