#!/usr/bin/env python3
"""Randomized local benchmark runner with private flag verification.

Smoke mode uses real local processes and artifact handoff without claiming to
be a model benchmark. Real mode is never silently skipped: without an explicit
backend credential/config it writes `not_run_missing_credentials`.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import random
import re
import shutil
import subprocess
import tempfile
import time
import zipfile

import yaml

from ctf_os.tactical_engine.profiles import ProblemClassifier
from ctf_os.tactical_engine.planners import default_planner_registry
from ctf_os.tactical_engine.strategies import StrategyExecutor


ROOT = Path(__file__).resolve().parents[1]


@dataclass
class ChallengeResult:
    id: str
    category: str
    subtype: str
    status: str
    strategy: str
    planner: str
    elapsed_sec: float
    flag_verified: bool
    failure_stage: str | None
    model_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost: float = 0.0
    tool_calls: int = 0
    tool_startup_failures: int = 0
    contract_success: int = 0
    contract_failure: int = 0
    artifact_handoff_count: int = 0
    artifact_handoff_success: int = 0
    replanning_count: int = 0
    replan_trigger_latency_sec: float | None = None
    cancelled_unnecessary_work: int = 0
    loop_detection_count: int = 0
    loop_escape_rate: float = 0.0
    false_loop_intervention: int = 0
    strategy_fallback_count: int = 0
    time_to_first_finding_sec: float | None = None
    time_to_primitive_sec: float | None = None
    time_to_verified_flag_sec: float | None = None
    cancelled_contract_count: int = 0
    artifact_handoffs: list[dict[str, object]] | None = None
    internal_solved_state: bool = False
    timeline: list[dict[str, object]] | None = None


def _event(timeline: list[dict[str, object]], type_: str, **payload: object) -> None:
    timeline.append({"type": type_, "timestamp": datetime.now(timezone.utc).isoformat(), **payload})


def _load() -> list[dict[str, object]]:
    raw = yaml.safe_load((ROOT / "benchmarks/challenges.yaml").read_text())
    if raw.get("schema_version") != 1 or len(raw.get("challenges", [])) < 12:
        raise ValueError("benchmark manifest requires schema v1 and at least 12 challenges")
    required = {"id", "category", "subtype", "strategy", "fixture", "smoke"}
    for item in raw["challenges"]:
        if set(item) != required:
            raise ValueError(f"invalid challenge manifest: {item.get('id')}")
    return raw["challenges"]


def _flag(rng: random.Random) -> str:
    return f"FLAG{{{rng.getrandbits(96):024x}}}"


def _run_fixture(item: dict[str, object], seed: int, root: Path, *, tactical: bool = True) -> ChallengeResult:
    started = time.monotonic()
    rng = random.Random(f"{seed}:{item['id']}")
    flag = _flag(rng)
    private = root / "verifier" / str(item["id"])
    workspace = root / "solver" / str(item["id"])
    artifacts = workspace / "artifacts"
    private.mkdir(parents=True)
    artifacts.mkdir(parents=True)
    (private / "expected.sha256").write_text(hashlib.sha256(flag.encode()).hexdigest())
    timeline: list[dict[str, object]] = []
    _event(timeline, "challenge.generated", seed=seed)
    profile = ProblemClassifier().classify(str(item["category"]),
        (f"{str(item['subtype']).replace('_', ' ')} {item['fixture']} benchmark archive zip password hash android apk terraform",))
    planner = default_planner_registry().plan(profile)
    _event(timeline, "problem.classified", subtype=profile.subtype, confidence=profile.confidence)
    _event(timeline, "strategy.selected", strategy=item["strategy"])
    if tactical:
        bootstrap = StrategyExecutor().bootstrap(str(item["strategy"]), workspace / "work", which=shutil.which)
        _event(timeline, "harness.bootstrap.completed", degraded=bootstrap.degraded)
    else:
        _event(timeline, "legacy.execution.started")
    fixture = str(item["fixture"])
    tool_calls = 0
    try:
        if fixture == "archive":
            archive = workspace / "evidence.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr(f"nested/{rng.randrange(1000,9999)}.txt", flag[::-1])
            subprocess.run(["unzip", "-qq", str(archive), "-d", str(artifacts)], check=True, timeout=10)
            tool_calls += 1
            recovered = next(artifacts.rglob("*.txt")).read_text()[::-1]
        elif fixture == "password":
            target = hashlib.sha256(flag.encode()).hexdigest()
            words = [f"FLAG{{{rng.getrandbits(96):024x}}}" for _ in range(50)] + [flag]
            rng.shuffle(words)
            (workspace / "hash.txt").write_text(target)
            (workspace / "wordlist.txt").write_text("\n".join(words))
            script = "import hashlib,sys\nt=open(sys.argv[1]).read().strip()\nfor w in open(sys.argv[2]):\n w=w.strip()\n if hashlib.sha256(w.encode()).hexdigest()==t: print(w);break\n"
            result = subprocess.run(["python3", "-c", script, str(workspace / "hash.txt"), str(workspace / "wordlist.txt")], check=True, text=True, capture_output=True, timeout=10)
            tool_calls += 1
            recovered = result.stdout.strip()
            (artifacts / "cracked.txt").write_text(recovered)
        elif fixture == "constraint":
            key = rng.randrange(1, 1 << 20)
            value = int(flag[5:13], 16) ^ key
            (workspace / "constraints.json").write_text(json.dumps({"xor": key, "value": value, "suffix": flag[13:]}))
            script = "import json,sys\nd=json.load(open(sys.argv[1])); print('FLAG{%08x%s'%((d['xor']^d['value']),d['suffix']))\n"
            result = subprocess.run(["python3", "-c", script, str(workspace / "constraints.json")], check=True, text=True, capture_output=True, timeout=10)
            tool_calls += 1
            recovered = result.stdout.strip()
            (artifacts / "solution.txt").write_text(recovered)
        else:
            # Full fixtures are infrastructure placeholders for real-model/nightly
            # mode; smoke mode never counts them as solved.
            return ChallengeResult(str(item["id"]), str(item["category"]), str(item["subtype"]),
                "not_run_requires_real_model", str(item["strategy"]), planner.planner_id,
                time.monotonic() - started, False, "model_execution", timeline=timeline)
        _event(timeline, "artifact.created", sha256=hashlib.sha256(recovered.encode()).hexdigest())
        verified = hashlib.sha256(recovered.encode()).hexdigest() == (private / "expected.sha256").read_text()
        _event(timeline, "artifact.handed_off", consumer="private-verifier")
        _event(timeline, "flag.verified", valid=verified)
        return ChallengeResult(str(item["id"]), str(item["category"]), str(item["subtype"]),
            "solved" if verified else "failed", str(item["strategy"]), planner.planner_id,
            time.monotonic() - started, verified, None if verified else "verification",
            tool_calls=tool_calls, contract_success=int(verified), contract_failure=int(not verified),
            artifact_handoff_count=1, artifact_handoff_success=1, timeline=timeline)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        _event(timeline, "contract.failed", error=f"{type(exc).__name__}: {exc}")
        return ChallengeResult(str(item["id"]), str(item["category"]), str(item["subtype"]),
            "failed", str(item["strategy"]), planner.planner_id, time.monotonic() - started,
            False, "tool_execution", tool_calls=tool_calls, tool_startup_failures=1, timeline=timeline)


def _report(results: list[ChallengeResult], *, mode: str, seed: int, provider: str | None = None) -> dict[str, object]:
    attempted = [item for item in results if item.status not in {"not_run_requires_real_model", "not_run_missing_credentials"}]
    solved = sum(item.flag_verified for item in attempted)
    return {
        "schema_version": 1, "mode": mode, "seed": seed, "provider": provider,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "summary": {"challenges": len(results), "attempted": len(attempted), "solved": solved,
                    "solve_rate": solved / len(attempted) if attempted else 0.0,
                    "valid_flag_rate": solved / len(attempted) if attempted else 0.0,
                    "tool_calls": sum(item.tool_calls for item in results),
                    "artifact_handoff_count": sum(item.artifact_handoff_count for item in results),
                    "artifact_handoff_success": sum(item.artifact_handoff_success for item in results)},
        "challenges": [asdict(item) for item in results],
    }


def _benchmark_plan(kind: str, *, tactical: bool = True):
    from ctf_os.solver_engine.category_planner import BranchExecutionSpec, ExecutionContract, SolvePlan
    from ctf_os.tactical_engine.rules import RuleParser

    def contract(identifier: str, role: str, objective: str, strategy: str, priority: int) -> ExecutionContract:
        profile = "luna_high" if role == "recon" else "terra_high"
        family = "recon" if strategy == "fast_recon" else "implementation"
        return ExecutionContract(
            id=identifier, worker=profile, session_role=role,
            exclusive_scope=f"benchmark {identifier}", objective=objective,
            first_decisive_action="execute the exact authorized target interaction in the objective",
            success_condition="emit the required structured artifact/finding or a verified flag candidate",
            stop_condition="stop at the stated contract boundary",
            handoff="structured artifact and exact commands",
            execution=BranchExecutionSpec("codex", profile, "high", family, 900, strategy, priority),
        )

    never = RuleParser().parse({
        "id": f"{kind}-noop", "priority": 1, "when": {"event": "benchmark.never"},
        "actions": [{"type": "escalate"}], "max_fires": 1,
    })
    if kind == "pwn-format":
        primary = contract(
            "format-exploit", "exploit",
            "Exploit the real format-string service at /workspace/target.sock using socat. "
            "The challenge binary is /workspace/chall. Build /artifacts/exploit.py that replays the socket exploit, "
            "run it, emit [ARTIFACT] /artifacts/exploit.py, then emit the real candidate.",
            "exploit_build" if tactical else "fast_recon", 90,
        )
        return SolvePlan("format string exploit", "state", "direct", (primary,), (never,), (never,))
    if kind == "pwn-heap":
        leak = contract(
            "allocator-leak", "reverse",
            "Connect exactly once to /workspace/target.sock and send LEAK. Save the exact JSON response as "
            "/artifacts/leak.json. Emit [ARTIFACT] /artifacts/leak.json first, then emit "
            "[FINDING] kind=libc_leak confidence=0.99 allocator safe-link primitive acquired. "
            "Do not send EXPLOIT and stop immediately after the finding.",
            "dynamic_analysis", 100,
        )
        spare = contract(
            "low-recon", "recon",
            "Inspect /workspace/chall statically only. Never connect to target.sock and do not consume the one-shot leak.",
            "fast_recon", 10,
        )
        rule = RuleParser().parse({
            "id": "heap-leak-to-exploit", "priority": 100,
            "when": {"event": "finding.created", "field": "finding.kind", "op": "eq", "value": "libc_leak"},
            "actions": [
                {"type": "cancel_contracts", "selector": {"tags_any": ["recon"]}},
                {"type": "promote_artifact", "artifact_type": "structured_result"},
                {"type": "spawn_plan", "planner": "pwn.heap.exploitation", "priority": 100},
            ], "cooldown_seconds": 30, "max_fires": 1,
        })
        return SolvePlan("allocator leak then exploit", "state", "parallel", (leak, spare), (rule,), (never,))
    if kind == "web-ssrf":
        probe = contract(
            "ssrf-probe", "reverse",
            "Use curl --unix-socket /workspace/origin.sock against http://challenge/fetch with the authorized "
            "internal.local/meta URL exactly once. Save the JSON response to /artifacts/endpoint.json. Emit "
            "[ARTIFACT] /artifacts/endpoint.json first, then [FINDING] kind=ssrf confirmed internal endpoint. "
            "Stop without requesting the returned admin endpoint.",
            "protocol_replay", 100,
        )
        spare = contract(
            "web-low-recon", "recon",
            "Inspect the origin root only; do not request /fetch or internal.local/meta.",
            "fast_recon", 10,
        )
        rule = RuleParser().parse({
            "id": "ssrf-to-internal-endpoint", "priority": 100,
            "when": {"event": "finding.created", "field": "finding.kind", "op": "eq", "value": "ssrf_confirmed"},
            "actions": [
                {"type": "cancel_contracts", "selector": {"tags_any": ["recon"]}},
                {"type": "promote_artifact", "artifact_type": "structured_result"},
                {"type": "spawn_plan", "planner": "web.ssrf.followup", "priority": 100},
            ], "cooldown_seconds": 30, "max_fires": 1,
        })
        return SolvePlan("SSRF endpoint then admin fetch", "protocol", "parallel", (probe, spare), (rule,), (never,))
    raise ValueError(f"unknown benchmark plan: {kind}")


def _start_target(
    *, kind: str, workspace: Path, flag: str, seed: int, image: str,
) -> tuple[str, dict[str, object]]:
    name = f"ctf-os-benchmark-{kind}-{seed}-{os.getpid()}"
    subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    env: list[str] = ["-e", f"BENCH_FLAG={flag}"]
    if kind == "pwn-heap":
        rng = random.Random(f"heap-service:{seed}")
        env += ["-e", f"BENCH_LEAK=0x{rng.getrandbits(48):x}",
                "-e", f"BENCH_SAFE_LINK_KEY=0x{rng.getrandbits(48):x}",
                "-e", f"BENCH_HANDLE={rng.getrandbits(96):024x}"]
    if kind == "web-ssrf":
        rng = random.Random(f"web-service:{seed}")
        env += ["-e", f"BENCH_NONCE={rng.getrandbits(80):020x}"]
        service = ROOT / "benchmarks/fixtures/ssrf_service.py"
        command = ["--entrypoint", "python3", "-v", f"{service}:/service.py:ro", image, "/service.py"]
        socket_name = "origin.sock"
    else:
        command = ["--entrypoint", "/shared/chall", image]
        socket_name = "target.sock"
    argv = [
        "docker", "run", "-d", "--name", name, "--network", "none",
        "--memory", "256m", "--cpus", "1", "--pids-limit", "64",
        "--security-opt", "no-new-privileges:true", "--cap-drop=ALL",
        "--label", "ctf-os-benchmark=true", *env,
        "-v", f"{workspace}:/shared:rw", *command,
    ]
    subprocess.run(argv, check=True, text=True, capture_output=True, timeout=30)
    socket_path = workspace / socket_name
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not socket_path.exists():
        time.sleep(.05)
    if not socket_path.exists():
        captured = subprocess.run(["docker", "logs", name], text=True, capture_output=True)
        logs = (captured.stdout + captured.stderr).strip()
        subprocess.run(["docker", "rm", "-f", name], text=True, capture_output=True, timeout=30)
        raise RuntimeError(f"target socket did not start: {logs[:500]}")
    return name, {"socket": socket_name, "network": "none", "memory": "256m", "cpus": 1, "pids": 64}


def _stop_target(name: str) -> bool:
    result = subprocess.run(["docker", "rm", "-f", name], text=True, capture_output=True, timeout=30)
    absent = subprocess.run(["docker", "inspect", name], text=True, capture_output=True, timeout=10).returncode != 0
    return result.returncode == 0 and absent


def _event_metrics(state, challenge, started_at: float, started_wall: datetime) -> dict[str, object]:
    events = state.list_events(challenge_id=challenge.id)
    timeline: list[dict[str, object]] = []
    for event in events:
        payload = event.payload
        safe_message = re.sub(r"(?:FLAG|CTF)\{[^}\r\n]{1,512}\}", "[REDACTED_FLAG]", event.message or "")
        timeline.append({
            "type": event.type, "timestamp": event.timestamp.isoformat(), "attempt_id": event.attempt_id,
            "message": safe_message[:500] if event.type in {
                "PLAN", "ACTION", "OBSERVATION", "FINDING", "FAIL", "WORKER_STOPPED", "FAILED",
                "rule.matched", "rule.executed", "artifact.created", "artifact.handed_off",
            } else None,
            "contract_id": payload.get("contract_id") or payload.get("producer_contract_id"),
            "strategy_id": payload.get("strategy_id"), "strategy_version": payload.get("strategy_version"),
            "profile": payload.get("profile"), "image": payload.get("image"), "rule_id": payload.get("rule_id"),
            "artifact_ids": payload.get("artifact_ids"), "consumer_contract_ids": payload.get("consumer_contract_ids"),
            "success": payload.get("success"), "candidate_sha256": payload.get("candidate_sha256"),
            "redacted": True if event.type in {"FLAG_OBSERVED", "flag.verified"} else None,
        })
    def elapsed_for(types: set[str]) -> float | None:
        event = next((item for item in events if item.type in types), None)
        return max(0.0, (event.timestamp - started_wall).total_seconds()) if event else None
    handoffs = [item for item in timeline if item["type"] == "artifact.handed_off"]
    by_id = {event.id: event for event in events}
    replan_latencies: list[float] = []
    for matched in (event for event in events if event.type == "rule.matched"):
        source = by_id.get(str(matched.payload.get("parent_event", "")))
        if source is not None:
            replan_latencies.append(max(0.0, (matched.timestamp - source.timestamp).total_seconds()))
    loop_events = [event for event in events if event.type in {"LOOP_DETECTED", "PLATEAU_DETECTED"}]
    loop_escapes = sum(any(
        later.timestamp > loop.timestamp and later.type in {"FINDING", "primitive.acquired", "artifact.created", "flag.verified"}
        for later in events
    ) for loop in loop_events)
    tasks = state.list_contract_tasks(state.get_challenge_session(challenge.id).id) if state.get_challenge_session(challenge.id) else []
    return {
        "events": events, "timeline": timeline, "handoffs": handoffs,
        "time_to_first_finding": elapsed_for({"FINDING"}),
        "time_to_primitive": elapsed_for({"primitive.acquired", "FINDING"}),
        "time_to_verified": elapsed_for({"flag.verified"}),
        "replan_latency": min(replan_latencies) if replan_latencies else None,
        "loop_escape_rate": loop_escapes / len(loop_events) if loop_events else 0.0,
        "cancelled_contracts": sum(item.status.value == "CANCELLED" for item in tasks),
        "internal_solved": challenge.status.value == "SOLVED",
    }


def _run_real_tactical_fixture(kind: str, seed: int, root: Path, *, tactical: bool = True) -> ChallengeResult:
    from ctf_os.application import LocalApplication
    from ctf_os.config import AppConfig, default_config_mapping
    from ctf_os.local_state import LocalState
    from ctf_os.models import Challenge
    from ctf_os.solver_engine.immutable_verifier import ParentOwnedVerifier

    started = time.monotonic()
    started_wall = datetime.now(timezone.utc)
    rng = random.Random(f"{kind}:{seed}")
    flag = _flag(rng)
    category = "web" if kind == "web-ssrf" else "pwn"
    name = {"pwn-format": "format", "pwn-heap": "heap", "web-ssrf": "ssrf"}[kind]
    subtype = {"pwn-format": "format_string", "pwn-heap": "heap.glibc", "web-ssrf": "ssrf"}[kind]
    strategy = ({"pwn-format": "exploit_build", "pwn-heap": "dynamic_analysis", "web-ssrf": "protocol_replay"}[kind]
                if tactical else "fast_recon")
    contest = f"Tactical {kind} {seed}"
    team, member = "benchmark-team", "benchmark-member"
    incoming = root / "incoming" / contest
    source_dir = incoming / category / name
    source_dir.mkdir(parents=True)
    description = {
        "pwn-format": "Native x86_64 printf format string service; exploit the actual socket target.",
        "pwn-heap": "glibc heap tcache safe-link allocator state challenge with a one-shot libc leak primitive.",
        "web-ssrf": "SSRF URL fetcher with a distinct internal endpoint and strict challenge-origin allowlist.",
    }[kind]
    (incoming / "contest.md").parent.mkdir(parents=True, exist_ok=True)
    (incoming / "contest.md").write_text(
        f"# 대회명: {contest}\n\n## 문제 목록\n\n### {category}/{name}\n"
        f"- 점수: 400\n- 설명: {description}\n",
    )
    if kind.startswith("pwn"):
        source = ROOT / "benchmarks/fixtures" / ("format_service.c" if kind == "pwn-format" else "heap_service.c")
        binary = source_dir / "chall"
        subprocess.run(["gcc", "-O2", "-static", "-s", str(source), "-o", str(binary)], check=True, timeout=30)
        binary.chmod(0o755)
    else:
        (source_dir / "README.txt").write_text("Authorized origin is exposed through /workspace/origin.sock.\n")

    raw = default_config_mapping(contest, team_id=team, member_name=member)
    raw["paths"] = {"incoming": str(root / "incoming"), "output": str(root / "output" / team / member)}
    raw["member"]["owned_categories"] = [category]
    raw["model_routing"] = {"enabled": True, "config_path": str(ROOT / "config/model-routing.yaml")}
    raw["sandbox"]["enabled"] = True
    raw["sandbox"]["image"] = os.environ.get("CTF_OS_SANDBOX_IMAGE", "ctf-os-sandbox:latest")
    raw["worker_policy"]["max_workers_total"] = 1
    raw["worker_policy"]["max_workers_per_challenge"] = 1
    raw.setdefault("supervision", {})["max_plan_revisions"] = 2
    raw["solver"]["tactical_engine"]["enabled"] = tactical
    config_path = root / "config.yaml"
    config_path.write_text(yaml.safe_dump(raw, sort_keys=False))
    target_name = ""
    cleanup_ok = False
    timeline: list[dict[str, object]] = []
    try:
        config = AppConfig.from_file(config_path)
        challenge_id = Challenge(contest, category, name).id
        verifier = ParentOwnedVerifier.from_flag(challenge_id=challenge_id, flag=flag)
        app = LocalApplication(
            config, parent_verifier=verifier,
            planner_plan_factory=lambda *_: _benchmark_plan(kind, tactical=tactical),
        )
        parsed = app.parse()
        if len(parsed) != 1:
            raise RuntimeError("benchmark fixture did not materialize exactly one challenge")
        workspace = parsed[0].workspace
        # The sandbox image intentionally runs as an unprivileged uid.  The
        # benchmark parent owns this fresh temporary directory and grants the
        # target container access only to this one fixture mount.
        workspace.chmod(0o777)
        challenge_binary = workspace / "chall"
        if challenge_binary.exists():
            challenge_binary.chmod(0o755)
        target_name, target_meta = _start_target(
            kind=kind, workspace=workspace, flag=flag, seed=seed, image=raw["sandbox"]["image"],
        )
        if kind == "web-ssrf":
            blocked = subprocess.run(
                ["curl", "--silent", "--output", "/dev/null", "--write-out", "%{http_code}",
                 "--unix-socket", str(workspace / "origin.sock"),
                 "http://challenge/fetch?url=http://example.com/"],
                text=True, capture_output=True, timeout=10, check=True,
            ).stdout
            if blocked != "403":
                raise RuntimeError(f"external SSRF allowlist probe returned {blocked}")
        app.run_once(mock_worker=False, auto_confirm_flags=False)
        state = LocalState.for_config(config)
        challenge = state.get_challenge(challenge_id)
        assert challenge is not None
        metrics = _event_metrics(state, challenge, started, started_wall)
        timeline = metrics["timeline"]
        events = metrics["events"]
        timeline.insert(0, {"type": "target.started", **target_meta, "redacted": True})
        cleanup_ok = _stop_target(target_name)
        target_name = ""
        timeline.append({"type": "target.cleanup", "success": cleanup_ok, "redacted": True})
        if not cleanup_ok:
            raise RuntimeError("benchmark target container cleanup failed")
        verified = bool(metrics["internal_solved"] and any(event.type == "flag.verified" for event in events))
        handoffs = [item for item in metrics["handoffs"] if item.get("success")]
        return ChallengeResult(
            f"{'tactical' if tactical else 'legacy'}-{kind}", category, subtype, "solved" if verified else "failed", strategy,
            str((state.get_problem_profile(challenge.id) or {}).get("subtype", "unknown")),
            time.monotonic() - started, verified, None if verified else "flag_verification",
            model_calls=sum(event.type == "WORKER_STARTED" for event in events),
            output_tokens=sum(int(event.payload.get("token_usage", 0) or 0) for event in events if event.type == "TOKEN_USAGE"),
            tool_calls=sum(event.type == "ACTION" for event in events),
            contract_success=sum(item.status.value == "SUCCEEDED" for item in state.list_contract_tasks(state.get_challenge_session(challenge.id).id)),
            contract_failure=sum(item.status.value == "FAILED" for item in state.list_contract_tasks(state.get_challenge_session(challenge.id).id)),
            artifact_handoff_count=len(metrics["handoffs"]), artifact_handoff_success=len(handoffs),
            replanning_count=sum(event.type == "rule.executed" for event in events),
            replan_trigger_latency_sec=metrics["replan_latency"],
            cancelled_unnecessary_work=int(metrics["cancelled_contracts"]),
            loop_detection_count=sum(event.type in {"LOOP_DETECTED", "PLATEAU_DETECTED"} for event in events),
            loop_escape_rate=float(metrics["loop_escape_rate"]),
            strategy_fallback_count=sum(event.type in {"MODEL_FALLBACK", "STRATEGY_FALLBACK"} for event in events),
            time_to_first_finding_sec=metrics["time_to_first_finding"],
            time_to_primitive_sec=metrics["time_to_primitive"],
            time_to_verified_flag_sec=metrics["time_to_verified"],
            cancelled_contract_count=int(metrics["cancelled_contracts"]), artifact_handoffs=handoffs,
            internal_solved_state=bool(metrics["internal_solved"]), timeline=timeline,
        )
    except Exception as exc:
        return ChallengeResult(
            f"{'tactical' if tactical else 'legacy'}-{kind}", category, subtype, "failed", strategy, subtype,
            time.monotonic() - started, False, f"{type(exc).__name__}: {exc}", timeline=timeline,
        )
    finally:
        if target_name:
            cleanup_ok = _stop_target(target_name)


def _run_real_ctfos(seed: int, root: Path) -> ChallengeResult:
    """Run one genuine Codex+Docker CTF-OS session against a randomized fixture."""
    from ctf_os.application import LocalApplication
    from ctf_os.config import AppConfig, default_config_mapping
    from ctf_os.local_state import LocalState
    from ctf_os.models import Challenge
    from ctf_os.solver_engine.immutable_verifier import ParentOwnedVerifier

    started = time.monotonic()
    rng = random.Random(f"real:{seed}")
    flag = _flag(rng)
    contest, team, member = "Tactical Benchmark", "benchmark-team", "benchmark-member"
    incoming = root / "incoming" / contest
    incoming.mkdir(parents=True)
    (incoming / "contest.md").write_text(
        f"# 대회명: {contest}\n\n## 문제 목록\n\n### forensics/recover\n"
        "- 점수: 100\n- 설명: Recover the flag from the supplied transformed artifact and create a replay verifier.\n",
    )
    source = incoming / "forensics" / "recover.zip"
    source.parent.mkdir(parents=True)
    with zipfile.ZipFile(source, "w") as handle:
        handle.writestr("nested/evidence.txt", flag[::-1])
    raw = default_config_mapping(contest, team_id=team, member_name=member)
    raw["paths"] = {"incoming": str(root / "incoming"), "output": str(root / "output" / team / member)}
    raw["member"]["owned_categories"] = ["forensics"]
    raw["model_routing"] = {"enabled": True, "config_path": str(ROOT / "config/model-routing.yaml")}
    raw["sandbox"]["enabled"] = True
    raw["sandbox"]["image"] = os.environ.get("CTF_OS_SANDBOX_IMAGE", "ctf-os-sandbox:latest")
    raw["worker_policy"]["max_workers_total"] = 2
    raw["worker_policy"]["max_workers_per_challenge"] = 2
    config_path = root / "config.yaml"
    config_path.write_text(yaml.safe_dump(raw, sort_keys=False))
    timeline: list[dict[str, object]] = []
    try:
        config = AppConfig.from_file(config_path)
        challenge_id = Challenge(contest, "forensics", "recover").id
        parent_verifier = ParentOwnedVerifier.from_flag(challenge_id=challenge_id, flag=flag)
        report = LocalApplication(config, parent_verifier=parent_verifier).run_once(
            mock_worker=False, auto_confirm_flags=False,
        )
        state = LocalState.for_config(config)
        challenge = state.list_challenges()[0]
        events = state.list_events(challenge_id=challenge.id)
        for event in events:
            timeline.append({
                "type": event.type, "timestamp": event.timestamp.isoformat(),
                "attempt_id": event.attempt_id,
                "strategy_id": event.payload.get("strategy_id"),
                "rule_id": event.payload.get("rule_id"),
                "model": event.payload.get("model"),
                "model_profile": event.payload.get("profile"),
                "outcome": event.payload.get("outcome"),
            })
        verified = challenge.status.value == "SOLVED" and any(
            event.type == "flag.verified" for event in events
        )
        return ChallengeResult(
            "real-forensics-recover", "forensics", "archive_polyglot",
            "solved" if verified else "failed", "artifact_recovery",
            str((state.get_problem_profile(challenge.id) or {}).get("subtype", "runtime-sol")),
            time.monotonic() - started, verified, None if verified else "flag_verification",
            model_calls=sum(event.type in {"WORKER_STARTED", "SESSION_LEADER_STARTED"} for event in events),
            output_tokens=sum(int(event.payload.get("token_usage", 0) or 0) for event in events if event.type == "TOKEN_USAGE"),
            tool_calls=sum(event.type == "ACTION" for event in events),
            contract_success=sum(event.type in {"WORKER_SUCCEEDED", "contract.completed"} for event in events),
            contract_failure=sum(event.type in {"WORKER_FAILED", "contract.failed"} for event in events),
            artifact_handoff_count=sum(event.type in {"artifact.handed_off", "ARTIFACT_PROMOTED"} for event in events),
            artifact_handoff_success=sum(event.type in {"artifact.handed_off", "ARTIFACT_PROMOTED"} for event in events),
            replanning_count=sum(event.type in {"rule.executed", "PLAN_REVISED"} for event in events),
            cancelled_unnecessary_work=sum(event.type == "contracts.cancelled" for event in events),
            loop_detection_count=sum(event.type in {"LOOP_DETECTED", "PLATEAU_DETECTED"} for event in events),
            strategy_fallback_count=sum(event.type in {"MODEL_FALLBACK", "STRATEGY_FALLBACK"} for event in events),
            timeline=timeline,
        )
    except Exception as exc:
        return ChallengeResult(
            "real-forensics-recover", "forensics", "archive_polyglot", "failed",
            "artifact_recovery", "runtime-sol", time.monotonic() - started, False,
            f"{type(exc).__name__}: {exc}", timeline=timeline,
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("smoke", "real", "compare", "compare-real"), default="smoke")
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--challenge", action="append", choices=(
        "pwn-format", "pwn-heap", "web-ssrf", "forensics-recover",
    ), help="real-mode fixture; repeatable")
    parser.add_argument("--output", type=Path, default=ROOT / "benchmarks/results")
    args = parser.parse_args()
    manifests = _load()
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ctf-os-benchmark-") as temporary:
        if args.mode == "real" and shutil.which("codex") is None:
            results = [ChallengeResult(str(item["id"]), str(item["category"]), str(item["subtype"]),
                "not_run_missing_credentials", str(item["strategy"]), "not_run", 0, False,
                "codex command is unavailable") for item in manifests]
        elif args.mode == "real":
            selected_real = args.challenge or ["pwn-heap", "forensics-recover"]
            results = [
                (_run_real_ctfos(args.seed, Path(temporary) / f"real-{name}")
                 if name == "forensics-recover"
                 else _run_real_tactical_fixture(name, args.seed, Path(temporary) / f"real-{name}"))
                for name in selected_real
            ]
        elif args.mode == "compare-real":
            selected_real = args.challenge or ["pwn-format"]
            baseline = [
                _run_real_tactical_fixture(name, args.seed, Path(temporary) / f"legacy-{name}", tactical=False)
                for name in selected_real if name != "forensics-recover"
            ]
            results = [
                _run_real_tactical_fixture(name, args.seed, Path(temporary) / f"tactical-{name}", tactical=True)
                for name in selected_real if name != "forensics-recover"
            ]
        elif args.mode == "compare":
            selected = [item for item in manifests if item["smoke"]]
            base_root = Path(temporary) / "baseline"
            tactical_root = Path(temporary) / "tactical"
            baseline = [_run_fixture(item, args.seed, base_root, tactical=False) for item in selected]
            results = [_run_fixture(item, args.seed, tactical_root, tactical=True) for item in selected]
        else:
            selected = [item for item in manifests if item["smoke"]] if args.mode == "smoke" else manifests
            results = [_run_fixture(item, args.seed, Path(temporary)) for item in selected]
        provider = "codex_cli" if args.mode == "real" and shutil.which("codex") else os.environ.get("OLLAMA_HOST")
        report = _report(results, mode=args.mode, seed=args.seed, provider=provider)
        report["run_config"] = {
            "provider": provider, "model_ids": sorted({
                str(event.get("model")) for item in results for event in (item.timeline or []) if event.get("model")
            }),
            "temperature": None, "seed": args.seed, "token_budget": None,
            "temperature_note": "Codex CLI backend does not expose a temperature control",
        }
        if args.mode in {"compare", "compare-real"}:
            report["baseline"] = [asdict(item) for item in baseline]
            report["comparison"] = {
                "same_seed": True,
                "solve_rate_delta": (sum(item.flag_verified for item in results) / len(results)) -
                                    (sum(item.flag_verified for item in baseline) / len(baseline)),
                "elapsed_sec_delta": sum(item.elapsed_sec for item in results) - sum(item.elapsed_sec for item in baseline),
                "model_calls_delta": sum(item.model_calls for item in results) - sum(item.model_calls for item in baseline),
                "tool_calls_delta": sum(item.tool_calls for item in results) - sum(item.tool_calls for item in baseline),
                "tokens_delta": sum(item.input_tokens + item.output_tokens for item in results) -
                                sum(item.input_tokens + item.output_tokens for item in baseline),
                "replanning_delta": sum(item.replanning_count for item in results) -
                                    sum(item.replanning_count for item in baseline),
                "artifact_handoff_delta": sum(item.artifact_handoff_success for item in results) -
                                          sum(item.artifact_handoff_success for item in baseline),
                "repeated_failure_delta": sum(item.loop_detection_count for item in results) -
                                          sum(item.loop_detection_count for item in baseline),
            }
    target = args.output / f"{args.mode}-{args.seed}.json"
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    markdown = [f"# CTF-OS benchmark: {args.mode}", "", f"Seed: `{args.seed}`", "",
                "| Challenge | Status | Planner | Strategy | Flag verified |", "|---|---|---|---|---|"]
    markdown += [f"| {item.id} | {item.status} | {item.planner} | {item.strategy} | {item.flag_verified} |" for item in results]
    target.with_suffix(".md").write_text("\n".join(markdown) + "\n")
    print(json.dumps(report["summary"], sort_keys=True))
    print(target)
    attempted = [item for item in results if item.status not in {"not_run_missing_credentials", "not_run_requires_real_model"}]
    return 0 if attempted and all(item.flag_verified for item in attempted) else 1


if __name__ == "__main__":
    raise SystemExit(main())
