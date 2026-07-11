from __future__ import annotations

from datetime import datetime, timedelta, timezone
from importlib import resources
import json
import multiprocessing
from pathlib import Path
from threading import Event as ThreadEvent

import pytest
import yaml

from ctf_os.application import LocalApplication
from ctf_os.config import AppConfig, default_config_mapping
from ctf_os.doctor import run_doctor
from ctf_os.flag_detector import FlagDetector
from ctf_os.local_state import LocalState, StateTransitionError
from ctf_os.local_event_state import LocalEventState
from ctf_os.models import Attempt, AttemptStatus, Challenge, ChallengeStatus, Event, FlagCandidate
from ctf_os.sandbox.docker_cli import CommandResult, DockerCli, RecordingCommandRunner
from ctf_os.solver_engine.codex_cli_backend import CodexExecResult
from ctf_os.solver_engine.parser import ActionObservationParser
from ctf_os.solver_engine.race_plan import RacePlan
from ctf_os.solver_engine.verifier import Verifier


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 7, 10, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


def _child_coordinator_claim(database: str, result_queue) -> None:
    state = LocalState(database)
    result_queue.put(state.claim_coordinator(contest="Demo", owner="child", lease_seconds=30).granted)


def _attempt(challenge_id: str, identifier: str, profile: str = "recon_fast") -> Attempt:
    return Attempt(id=identifier, challenge_id=challenge_id, profile=profile, role="recon", backend="mock", workdir="/work")


def test_sqlite_leases_are_contention_safe_recover_stale_and_keep_solved_immutable(tmp_path: Path) -> None:
    clock = Clock()
    one = LocalState(tmp_path / "state.db", clock=clock)
    two = LocalState(tmp_path / "state.db", clock=clock)
    challenge = one.upsert_challenge(Challenge(contest="Demo", category="web", name="login"))
    one.transition_challenge_status(challenge.id, "QUEUED")
    assert one.claim_coordinator(contest="Demo", owner="process-a", lease_seconds=10).granted
    assert not two.claim_coordinator(contest="Demo", owner="process-b", lease_seconds=10).granted
    one.release_coordinator(contest="Demo", owner="process-a")
    first = one.claim_attempt(_attempt(challenge.id, "a"), owner="process-a", lease_seconds=5, max_workers_total=1, max_workers_per_challenge=1)
    assert first.granted and first.fencing_token is not None
    assert not two.claim_attempt(_attempt(challenge.id, "b"), owner="process-b", lease_seconds=5, max_workers_total=1, max_workers_per_challenge=1).granted
    one.transition_challenge_status(
        challenge.id, "RUNNING", attempt_id="a",
        owner="process-a", fencing_token=first.fencing_token,
    )
    clock.advance(6)
    recovered = two.reconcile_stale_attempts()
    assert recovered.stale_attempt_ids == ("a",)
    assert recovered.requeued_challenge_ids == (challenge.id,)
    assert two.get_attempt("a").status is AttemptStatus.STOPPED
    assert two.get_challenge(challenge.id).status is ChallengeStatus.QUEUED
    second = two.claim_attempt(_attempt(challenge.id, "b"), owner="process-b", lease_seconds=5, max_workers_total=1, max_workers_per_challenge=1)
    assert second.granted and second.fencing_token is not None
    two.transition_challenge_status(
        challenge.id, "RUNNING", attempt_id="b",
        owner="process-b", fencing_token=second.fencing_token,
    )
    candidate = FlagCandidate(challenge_id=challenge.id, attempt_id="b", value="FLAG{REAL}")
    two.record_candidate(
        candidate,
        Event(team_id="team", member="m", contest="Demo", type="FLAG_CANDIDATE", challenge_id=challenge.id, attempt_id="b"),
        owner="process-b",
        fencing_token=second.fencing_token,
    )
    event = Event(team_id="team", member="m", contest="Demo", type="SOLVED", challenge_id=challenge.id, payload={"flag": "FLAG{REAL}"})
    two.solve_verified(candidate_id=candidate.id, flag="FLAG{REAL}", event=event,
                       owner="process-b", fencing_token=second.fencing_token)
    with pytest.raises(StateTransitionError, match="immutable"):
        two.transition_challenge_status(challenge.id, "QUEUED")


def test_coordinator_lease_rejects_a_separate_cli_process(tmp_path: Path) -> None:
    database = tmp_path / "state.db"
    state = LocalState(database)
    assert state.claim_coordinator(contest="Demo", owner="parent", lease_seconds=30).granted
    context = multiprocessing.get_context("spawn")
    result_queue = context.Queue()
    child = context.Process(target=_child_coordinator_claim, args=(str(database), result_queue))
    child.start()
    child.join(10)
    assert child.exitcode == 0 and result_queue.get(timeout=2) is False


def test_verifier_refuses_worker_owned_artifacts_and_reports_unavailable(tmp_path: Path) -> None:
    work = tmp_path / "work"
    output = tmp_path / "output"
    work.mkdir()
    replay = work / "replay.py"
    replay.write_text("print('checked')\n", encoding="utf-8")
    records = ActionObservationParser().parse("[ARTIFACT] /work/replay.py")
    verifier = Verifier()
    command = verifier.derive_command(
        records, attempt_workdir=work, challenge_artifacts=output,
        candidate="FLAG{REAL}", challenge_id="chal", attempt_id="attempt-a", nonce="nonce-a",
    )
    assert command is None
    unavailable = verifier.verify_sandbox("FLAG{REAL}", None, execute=lambda _argv: None)
    assert unavailable.state == "rejected"
    assert verifier.derive_command(
        ActionObservationParser().parse("[ARTIFACT] /work/made-up.sh"),
        attempt_workdir=work, challenge_artifacts=output,
        candidate="FLAG{REAL}", challenge_id="chal", attempt_id="attempt-a", nonce="nonce-b",
    ) is None


def test_custom_patterns_synthetic_isolation_and_active_attempt_reduction() -> None:
    assert FlagDetector([r"CUSTOM\[[^\]]+\]"]).detect("CUSTOM[real]") == ["CUSTOM[real]"]
    now = datetime(2026, 7, 10, tzinfo=timezone.utc)
    events = [
        Event(timestamp=now, team_id="t", member="alice", contest="D", type="WORKER_STARTED", challenge_id="c", attempt_id="a"),
        Event(timestamp=now, team_id="t", member="alice", contest="D", type="FINDING", challenge_id="c", attempt_id="a"),
        Event(timestamp=now, team_id="t", member="bob", contest="D", type="WORKER_STARTED", challenge_id="c", attempt_id="b"),
        Event(timestamp=now, team_id="t", member="eve", contest="D", type="SOLVED", challenge_id="synthetic", payload={"flag": "SYNTHETIC{X}", "synthetic": True}),
    ]
    state = LocalEventState.from_events(events)
    merged = state.get("c")
    assert merged and merged.running_members == ("alice", "bob") and merged.duplicate_running
    assert state.get("synthetic") is None


def _runtime_config(tmp_path: Path) -> AppConfig:
    raw = default_config_mapping("Demo")
    raw["member"]["owned_categories"] = ["web", "misc"]
    raw["sandbox"]["enabled"] = True
    raw["model_routing"]["enabled"] = True
    route = tmp_path / "routing.yaml"
    route.write_text(
        "model_profiles:\n  primary:\n    model: gpt-5.6-terra\n    reasoning_effort: high\n    fallback: gpt-5.5\n    fallback_reasoning_effort: medium\n"
        "default_roles:\n  recon: primary\n  exploit: primary\n  source: primary\n  fallback: primary\n"
        "model_policy:\n  easy:\n    recon_fast: primary\n    exploit_fast: primary\n",
        encoding="utf-8",
    )
    raw["model_routing"]["config_path"] = "routing.yaml"
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    return AppConfig.from_file(path)


def test_model_cooldown_selects_only_configured_fallback_and_doctor_requires_real_prerequisites(tmp_path: Path) -> None:
    config = _runtime_config(tmp_path)
    state = LocalState(config.state_path())
    challenge = state.upsert_challenge(Challenge(contest="Demo", category="web", name="login", score=1))
    app = LocalApplication(config, docker=DockerCli(runner=RecordingCommandRunner()), command_exists=lambda _name: "/fake/codex")
    selected = app._select_model(state, challenge, RacePlan.for_score(1).attempts[0])
    assert selected.model == "gpt-5.6-terra"
    state.set_model_cooldown("gpt-5.6-terra", reason="rate limited", seconds=30)
    assert app._select_model(state, challenge, RacePlan.for_score(1).attempts[0]).model == "gpt-5.5"
    report = run_doctor(config.path, docker=DockerCli(runner=RecordingCommandRunner(returncode=1)), which=lambda _name: None, require_non_mock=True)
    assert report.exit_code == 1
    assert any(check.name == "codex" and check.required and not check.ok for check in report.checks)
    strict_failed = run_doctor(
        config.path,
        docker=DockerCli(runner=RecordingCommandRunner()),
        which=lambda _name: "/fake/tool",
        strict_isolation_probe=lambda _command: False,
        require_non_mock=True,
    )
    assert strict_failed.exit_code == 1
    assert any(check.name == "codex strict isolation" and check.required and not check.ok for check in strict_failed.checks)
    strict_ok = run_doctor(
        config.path,
        docker=DockerCli(runner=RecordingCommandRunner()),
        which=lambda _name: "/fake/tool",
        strict_isolation_probe=lambda _command: True,
        require_non_mock=True,
    )
    assert any(check.name == "codex strict isolation" and check.ok for check in strict_ok.checks)
    assert any(
        check.name == "attempt filesystem spool transport"
        and "authenticated filesystem spool atomic publish" in check.detail
        for check in strict_ok.checks
    )


def test_package_asset_is_available_after_install() -> None:
    asset = resources.files("ctf_os.resources").joinpath("model-routing.yaml")
    assert asset.is_file() and "model_profiles:" in asset.read_text(encoding="utf-8")


def _manifest(tmp_path: Path, text: str) -> None:
    path = tmp_path / "incoming" / "Demo" / "contest.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _source(tmp_path: Path, category: str, name: str) -> None:
    source = tmp_path / "incoming" / "Demo" / category / name
    source.mkdir(parents=True, exist_ok=True)
    (source / "challenge.txt").write_text("ready\n", encoding="utf-8")


def test_streamed_worker_replay_remains_candidate_and_never_cancels_other_attempts(tmp_path: Path) -> None:
    config = _runtime_config(tmp_path)
    _manifest(tmp_path, """# 대회명: Demo

### web/login
- 점수: 1

### misc/keep-running
- 점수: 1
""")
    _source(tmp_path, "web", "login")
    _source(tmp_path, "misc", "keep-running")
    cancellations: dict[str, list[ThreadEvent]] = {}

    class StreamingCodex:
        def run(self, request, **kwargs):
            cancelled = kwargs["cancel_event"]
            category = "web" if "- category: web" in request.prompt else "misc"
            cancellations.setdefault(category, []).append(cancelled)
            if category == "web":
                (request.workdir / "replay.py").write_text("print('replay')\n", encoding="utf-8")
                kwargs["on_output"](type("Record", (), {"line": "[ARTIFACT] /work/replay.py"})())
                kwargs["on_output"](type("Record", (), {"line": "[FLAG_CANDIDATE] FLAG{STREAMED}"})())
                cancelled.wait(1)
            else:
                cancelled.wait(0.05)
            return CodexExecResult(tuple(), 0, "", "")

    def runner(argv: list[str]) -> CommandResult:
        if argv[:2] == ["docker", "exec"] and "/work/replay.py" in argv:
            proof = {
                "candidate": argv[argv.index("--candidate") + 1],
                "challenge_id": argv[argv.index("--challenge-id") + 1],
                "attempt_id": argv[argv.index("--attempt-id") + 1],
                "nonce": argv[argv.index("--nonce") + 1],
            }
            return CommandResult(tuple(argv), stdout=f"[VERIFICATION_PROOF] {json.dumps(proof, separators=(',', ':'))}\n")
        return CommandResult(tuple(argv))

    docker = DockerCli(runner=runner)
    app = LocalApplication(config, docker=docker, codex_backend_factory=lambda **_: StreamingCodex(), command_exists=lambda _name: "/fake/codex")
    report = app.run_once()
    state = LocalState(config.state_path())
    challenges = {item.name: item for item in state.list_challenges()}
    web, misc = challenges["login"], challenges["keep-running"]
    assert report.solved_challenges == 0 and web.status is ChallengeStatus.FLAG_CANDIDATE
    assert misc.status is ChallengeStatus.FAILED
    assert cancellations["web"] and all(not event.is_set() for event in cancellations["web"])
    assert cancellations["misc"] and all(not event.is_set() for event in cancellations["misc"])


def test_attempt_exception_finalizes_container_and_persists_cleanup(tmp_path: Path) -> None:
    config = _runtime_config(tmp_path)
    _manifest(tmp_path, "# 대회명: Demo\n\n### web/login\n- 점수: 1\n")
    _source(tmp_path, "web", "login")

    class BrokenCodex:
        def run(self, _request, **_kwargs):
            raise RuntimeError("backend boom")

    runner = RecordingCommandRunner()
    app = LocalApplication(config, docker=DockerCli(runner=runner), codex_backend_factory=lambda **_: BrokenCodex(), command_exists=lambda _name: "/fake/codex")
    app.run_once()
    state = LocalState(config.state_path())
    attempts = state.list_attempts(state.list_challenges()[0].id)
    assert attempts and all(item.status is AttemptStatus.FAILED and item.cleanup_status == "CLEANED" for item in attempts)
    assert any(call[:3] == ["docker", "rm", "-f"] for call in runner.calls)


def test_startup_orphan_cleanup_never_removes_an_attempt_with_a_live_lease(tmp_path: Path) -> None:
    config = _runtime_config(tmp_path)
    state = LocalState(config.state_path())
    challenge = state.upsert_challenge(Challenge(contest="Demo", category="web", name="login"))
    state.transition_challenge_status(challenge.id, "QUEUED")
    active = Attempt(id="active-attempt", challenge_id=challenge.id, profile="recon_fast", role="recon", backend="codex_cli", workdir="/work", container_name="active-name")
    assert state.claim_attempt(active, owner="owner", lease_seconds=30, max_workers_total=2, max_workers_per_challenge=2).granted
    calls: list[list[str]] = []

    def runner(argv: list[str]) -> CommandResult:
        calls.append(argv)
        if argv[1:3] == ["ps", "-aq"]:
            return CommandResult(tuple(argv), stdout="active-id\n" if any("attempt_id=active-attempt" in item for item in argv) else "active-id\norphan-id\n")
        return CommandResult(tuple(argv))

    app = LocalApplication(config, docker=DockerCli(runner=runner))
    assert app._cleanup_orphan_containers(state) == ["orphan-id"]
    assert [call for call in calls if call[:3] == ["docker", "rm", "-f"]] == [["docker", "rm", "-f", "orphan-id"]]
