"""Operator and agent CLI for the challenge-scoped CTF-OS engine."""

from __future__ import annotations

import argparse
import json
import math
import os
import stat
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from ctf_os.config import (
    ConfigError,
    default_config_text,
    load_config,
    set_runtime_image_digest,
)
from ctf_os.doctor import collect_diagnostics
from ctf_os.engine.challenge import (
    ChallengeEngine,
    EngineError,
    SessionAlreadyRunning,
)
from ctf_os.evaluation import EvaluationError, evaluate_workspace
from ctf_os.images import image_status_is_usable, inspect_local_image
from ctf_os.knowledge import KnowledgeError, KnowledgeStore
from ctf_os.live_broker import (
    INSPECT_SECTIONS,
    LIVE_SCOPE_CAPABILITY_ENV,
    MAX_INSPECT_OFFSET,
    MAX_INSPECT_PAGE_ITEMS,
    LiveBrokerClient,
    LiveBrokerError,
    inspect_state,
)
from ctf_os.models import (
    ChallengeIdentity,
    ChallengeStatus,
    ExperimentStatus,
    HypothesisStatus,
    Provenance,
)
from ctf_os.sandbox import NetworkTarget, SandboxError
from ctf_os.store import StateStoreError
from ctf_os.store.atomic import atomic_write_json, atomic_write_text
from ctf_os.terminal import terminal_safe


class CLIError(RuntimeError):
    def __init__(self, message: str, exit_code: int = 2) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def _inspect_offset_argument(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "offset must be an integer"
        ) from error
    if not 0 <= parsed <= MAX_INSPECT_OFFSET:
        raise argparse.ArgumentTypeError(
            f"offset must be between 0 and {MAX_INSPECT_OFFSET}"
        )
    return parsed


def _inspect_limit_argument(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "limit must be an integer"
        ) from error
    if not 1 <= parsed <= MAX_INSPECT_PAGE_ITEMS:
        raise argparse.ArgumentTypeError(
            f"limit must be between 1 and {MAX_INSPECT_PAGE_ITEMS}"
        )
    return parsed


def _identity_values(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("contest", metavar="CONTEST")
    parser.add_argument("category", metavar="CATEGORY")
    parser.add_argument("challenge", metavar="CHALLENGE")


def _scope_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--contest")
    parser.add_argument("--category")
    parser.add_argument("--challenge")


def _read_bounded_text(path: Path, *, maximum: int = 1024 * 1024) -> str:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as error:
        raise CLIError(f"프롬프트 파일을 읽을 수 없습니다: {error}") from error
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise CLIError("프롬프트 입력은 일반 파일이어야 합니다.")
    if metadata.st_size > maximum:
        raise CLIError(f"프롬프트 파일은 {maximum} bytes 이하여야 합니다.")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise CLIError(f"UTF-8 프롬프트를 읽을 수 없습니다: {error}") from error


def _prompt(args: argparse.Namespace) -> str | None:
    inline = getattr(args, "prompt", None)
    prompt_file = getattr(args, "prompt_file", None)
    if inline is not None and prompt_file is not None:
        raise CLIError("PROMPT와 --prompt-file은 동시에 쓸 수 없습니다.")
    if prompt_file is not None:
        return _read_bounded_text(prompt_file)
    return inline


def _identity(args: argparse.Namespace) -> ChallengeIdentity:
    return ChallengeIdentity(args.contest, args.category, args.challenge)


def _verify_session_scope(
    identity: ChallengeIdentity,
    engine: ChallengeEngine,
) -> None:
    """Enforce exact scope whenever a command runs in a live-session env."""

    session_values = tuple(
        os.environ.get(name)
        for name in ("CTFOS_CONTEST", "CTFOS_CATEGORY", "CTFOS_CHALLENGE")
    )
    token = (
        os.environ.get(LIVE_SCOPE_CAPABILITY_ENV)
        or os.environ.get("CTFOS_SCOPE_TOKEN")
    )
    if token is None:
        if any(value is not None for value in session_values):
            raise CLIError(
                "CTF-OS 세션 환경에는 scope capability가 필요합니다. "
                "다른 문제로 우회 실행하지 않습니다."
            )
        # Explicit identity without session variables is the human/operator
        # path. It remains available outside attached Codex sessions.
        return

    from ctf_os.sandbox.daemon import (
        CapabilityAuthority,
        CapabilityError,
    )

    authority = CapabilityAuthority.from_file(
        engine.config.state_root / "runtime" / "capability-secret"
    )
    try:
        claimed_scope = authority.verify(token)
    except CapabilityError as error:
        raise CLIError(f"만료되었거나 잘못된 세션 capability: {error}") from error
    state = engine.store.load(identity)
    actual_scope = engine.sandbox(state).scope_fingerprint
    if claimed_scope != actual_scope:
        raise CLIError(
            "현재 세션 capability는 다른 문제 scope에 접근할 수 없습니다."
        )


def _scoped_identity(
    args: argparse.Namespace, engine: ChallengeEngine
) -> ChallengeIdentity:
    contest = args.contest or os.environ.get("CTFOS_CONTEST")
    category = args.category or os.environ.get("CTFOS_CATEGORY")
    challenge = args.challenge or os.environ.get("CTFOS_CHALLENGE")
    if not contest or not category or not challenge:
        raise CLIError(
            "scope가 없습니다. --contest/--category/--challenge를 모두 "
            "지정하거나 CTF-OS 세션 안에서 실행하세요."
        )
    identity = ChallengeIdentity(contest, category, challenge)
    _verify_session_scope(identity, engine)
    return identity


def _live_identity(args: argparse.Namespace) -> ChallengeIdentity:
    contest = getattr(args, "contest", None) or os.environ.get("CTFOS_CONTEST")
    category = getattr(args, "category", None) or os.environ.get("CTFOS_CATEGORY")
    challenge = getattr(args, "challenge", None) or os.environ.get(
        "CTFOS_CHALLENGE"
    )
    if not contest or not category or not challenge:
        raise CLIError(
            "Live scope가 없습니다. 세션을 닫고 `ctfos solve`로 다시 시작하세요."
        )
    return ChallengeIdentity(contest, category, challenge)


def _broker_dict(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CLIError("Live broker가 잘못된 응답을 반환했습니다.")
    return value


def _run_live_broker_command(
    args: argparse.Namespace,
    client: LiveBrokerClient,
) -> int:
    """Route the only commands available to an attached Live child."""

    if args.command not in {"agent", "tool", "jobs", "inspect"}:
        raise CLIError(
            "Live 세션에서는 agent/tool/jobs/inspect만 사용할 수 있습니다. "
            "제출·예산·target 변경은 사람의 별도 터미널에서 실행하세요."
        )
    identity = _live_identity(args)

    if args.command == "inspect":
        params: dict[str, object] = {"section": args.section}
        if args.offset is not None:
            params["offset"] = args.offset
        if args.limit is not None:
            params["limit"] = args.limit
        result = client.call(
            "inspect",
            identity,
            params,
            timeout=30,
        )
        _print_json(result)
        return 0

    if args.command == "jobs":
        result = _broker_dict(client.call("jobs", identity))
        _print_json(result)
        return 0

    if args.command == "tool":
        command = _strip_remainder(args.tool_argv)
        result = _broker_dict(
            client.call(
                "tool.run",
                identity,
                {
                    "command": list(command),
                    "expected_observation": args.expected,
                    "keep_if": args.keep_if,
                    "drop_if": args.drop_if,
                    "hypothesis_ids": list(args.hypothesis),
                    "timeout_seconds": args.timeout,
                    "resource_class": args.profile,
                    "network_target": args.target,
                    "needs_kvm": args.kvm,
                },
            )
        )
        _print_json(result)
        return 0

    if args.agent_command == "flag":
        result = _broker_dict(
            client.call(
                "agent.flag",
                identity,
                {
                    "value": args.value,
                    "source": args.source,
                    "source_run_id": args.source_run,
                },
                timeout=30,
            )
        )
        print(f"candidate 기록: {result['candidate_id']}")
        return 0

    if args.agent_command == "fact":
        result = _broker_dict(
            client.call(
                "agent.fact",
                identity,
                {
                    "statement": args.statement,
                    "provenance": args.provenance,
                    "source_run_id": args.source_run,
                    "artifact_id": args.artifact,
                    "locator": args.locator,
                },
                timeout=30,
            )
        )
        print(f"fact 기록: {result['fact_id']}")
        return 0

    if args.agent_command == "experiment":
        command = _strip_remainder(args.experiment_argv)
        result = _broker_dict(
            client.call(
                "agent.experiment",
                identity,
                {
                    "command": list(command),
                    "expected_observation": args.expected,
                    "keep_if": args.keep_if,
                    "drop_if": args.drop_if,
                    "hypothesis_ids": list(args.hypothesis),
                    "timeout_seconds": args.timeout,
                    "resource_class": args.profile,
                    "network_target": args.target,
                    "needs_kvm": args.kvm,
                },
                timeout=30,
            )
        )
        print(f"experiment 사전 등록: {result['experiment_id']}")
        return 0

    if args.agent_command == "goal":
        result = _broker_dict(
            client.call(
                "agent.goal",
                identity,
                {
                    "action": args.action,
                    "goal_id": args.goal_id,
                    "description": args.description,
                    "depends_on": list(args.depends_on),
                    "artifact_ids": list(args.artifact),
                    "blocked_reason": args.blocked_reason,
                    "activate": args.activate,
                },
                timeout=30,
            )
        )
        print(
            f"goal 갱신: {result['goal_id']} "
            f"status={result['status']} "
            f"active={result['active_goal_id'] or '-'}"
        )
        return 0

    if args.agent_command == "hypothesis":
        result = _broker_dict(
            client.call(
                "agent.hypothesis",
                identity,
                {
                    "action": args.action,
                    "hypothesis_id": args.hypothesis_id,
                    "statement": args.statement,
                    "falsifier": args.falsifier,
                    "status": args.status,
                    "evidence_fact_ids": list(args.evidence_fact),
                    "evidence_artifact_ids": list(
                        args.evidence_artifact
                    ),
                    "evidence_run_ids": list(args.evidence_run),
                    "confidence": args.confidence,
                    "refuted_by": args.refuted_by,
                },
                timeout=30,
            )
        )
        print(
            f"hypothesis 갱신: {result['hypothesis_id']} "
            f"status={result['status']}"
        )
        return 0

    if args.agent_command == "evaluate":
        result = _broker_dict(
            client.call(
                "agent.evaluate",
                identity,
                {
                    "experiment_id": args.experiment_id,
                    "status": args.status,
                    "reason": args.reason,
                    "evidence_fact_ids": list(args.evidence_fact),
                    "evidence_artifact_ids": list(
                        args.evidence_artifact
                    ),
                    "evidence_run_ids": list(args.evidence_run),
                    "support_hypothesis_ids": list(args.support),
                    "refute_hypothesis_ids": list(args.refute),
                },
                timeout=30,
            )
        )
        print(
            f"experiment 평가: {result['experiment_id']} "
            f"status={result['status']}"
        )
        return 0

    if args.agent_command == "artifact":
        if args.source_run is not None:
            raise CLIError(
                "Live artifact에는 --source-run을 지정할 수 없습니다. "
                "실행 증거는 엔진이 tool 결과에서 연결합니다."
            )
        result = _broker_dict(
            client.call(
                "agent.artifact",
                identity,
                {"locator": args.locator},
                timeout=30,
            )
        )
        print(
            f"artifact 등록: {result['artifact_id']} "
            f"sha256={result['sha256']}"
        )
        return 0

    if args.agent_command == "progress":
        result = _broker_dict(
            client.call(
                "agent.progress",
                identity,
                {
                    "statement": args.statement,
                    "run_id": args.run,
                    "artifact_ids": list(args.artifact),
                },
                timeout=30,
            )
        )
        print(f"progress 기록: {result['progress_id']}")
        return 0

    if args.agent_command == "transition":
        result = _broker_dict(
            client.call(
                "agent.transition",
                identity,
                {"target": args.target},
                timeout=30,
            )
        )
        print(f"transition: {result['status']}")
        return 0

    raise AssertionError(f"처리되지 않은 Live agent 명령: {args.agent_command}")


def _parse_challenge_spec(value: str) -> tuple[str, str]:
    if value.count("/") != 1 or "\\" in value:
        raise CLIError("문제는 정확히 CATEGORY/CHALLENGE 형식이어야 합니다.")
    category, challenge = value.split("/", 1)
    if not category.strip() or not challenge.strip():
        raise CLIError("카테고리와 문제 이름은 비어 있을 수 없습니다.")
    return category, challenge


def _strip_remainder(command: Sequence[str]) -> tuple[str, ...]:
    values = tuple(command)
    if values and values[0] == "--":
        values = values[1:]
    if not values:
        raise CLIError("'--' 뒤에 실행할 명령을 지정하세요.")
    return values


def _json_default(value: object) -> object:
    if hasattr(value, "to_dict"):
        return value.to_dict()  # type: ignore[no-any-return]
    if hasattr(value, "value"):
        return value.value  # type: ignore[no-any-return]
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"not JSON serializable: {type(value).__name__}")


def _print_json(value: object) -> None:
    print(
        terminal_safe(
            json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            default=_json_default,
            ),
            multiline=True,
        )
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctfos",
        description=(
            "사람이 문제 세션을 열고, CTF-OS가 상태·역할·샌드박스·proof를 "
            "관리합니다. 스케줄러와 자동 제출은 없습니다."
        ),
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help="workspace root (기본: 현재 디렉터리)",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("init", help=".ctfos/engine.toml 기본 설정 생성")
    commands.add_parser(
        "pin-image",
        help="현재 runtime.image의 정확한 로컬 Docker image ID 고정",
    )
    doctor = commands.add_parser("doctor", help="호스트/도구 환경 진단")
    doctor.add_argument("--calibrate", action="store_true")

    init_contest = commands.add_parser(
        "init-contest", help="호환 명령: 대회와 문제 폴더 생성"
    )
    init_contest.add_argument("contest")
    init_contest.add_argument("--challenge", required=True)

    add = commands.add_parser(
        "add-challenge", help="사람이 파일을 넣을 문제 폴더와 상태 생성"
    )
    _identity_values(add)
    add.add_argument("--description", default="")
    add.add_argument("--prompt")
    add.add_argument("--prompt-file", type=Path)
    add.add_argument("--target", action="append", default=[])
    add.add_argument("--budget-seconds", type=int)

    target = commands.add_parser(
        "add-target", help="문제별 허용 원격 endpoint 추가"
    )
    _identity_values(target)
    target.add_argument("target")
    target.add_argument("--docker-network", default="bridge")
    target.add_argument(
        "--enforcement", choices=("declared", "proxy"), default="declared"
    )

    knowledge = commands.add_parser(
        "knowledge",
        help="사람이 검증한 로컬 논문/소스 자료를 불변 provenance로 관리",
    )
    knowledge_commands = knowledge.add_subparsers(
        dest="knowledge_command",
        required=True,
    )
    knowledge_add = knowledge_commands.add_parser("add")
    _identity_values(knowledge_add)
    knowledge_add.add_argument("file", type=Path)
    knowledge_add.add_argument("--source", required=True)
    knowledge_add.add_argument("--title")
    knowledge_add.add_argument("--sha256")
    knowledge_add.add_argument(
        "--kind",
        choices=("full_text", "source", "notes"),
        default="full_text",
    )
    knowledge_list = knowledge_commands.add_parser("list")
    _identity_values(knowledge_list)
    knowledge_search = knowledge_commands.add_parser("search")
    _identity_values(knowledge_search)
    knowledge_search.add_argument("query")
    knowledge_search.add_argument("--limit", type=int, default=10)

    solve = commands.add_parser(
        "solve",
        help="Live Captain 세션 준비/시작 (초기화·model 호출 대기 가능)",
    )
    _identity_values(solve)
    solve.add_argument("prompt", nargs="?")
    solve.add_argument("--prompt-file", type=Path)
    solve.add_argument("--resume-thread")

    run = commands.add_parser(
        "run-challenge", help="결정적 Captain/3-role Batch 실행"
    )
    _identity_values(run)
    run.add_argument("--prompt")
    run.add_argument("--prompt-file", type=Path)
    run.add_argument("--max-cycles", type=int, default=8)
    run.add_argument("--no-tools", action="store_true")

    status = commands.add_parser("status", help="읽기 전용 대회 board")
    status.add_argument("contest", nargs="?")
    status.add_argument("--json", action="store_true")
    status.add_argument("--watch", action="store_true")
    status.add_argument("--interval", type=float, default=2.0)

    evaluation = commands.add_parser(
        "evaluate",
        help="저장된 정본 상태/실행 기록만 결정론적으로 집계",
    )
    evaluation.add_argument("--contest")
    evaluation.add_argument("--category")
    evaluation.add_argument("--challenge")

    leases = commands.add_parser("leases", help="도구/model 대기 상태")
    leases.add_argument("--json", action="store_true")

    inspect = commands.add_parser("inspect", help="문제 정본 상태 조회")
    _identity_values(inspect)
    inspect.add_argument(
        "section",
        choices=INSPECT_SECTIONS,
    )
    inspect.add_argument(
        "--offset",
        type=_inspect_offset_argument,
        help="목록 section의 0-based 시작 위치",
    )
    inspect.add_argument(
        "--limit",
        type=_inspect_limit_argument,
        help=f"목록 page 크기 (최대 {MAX_INSPECT_PAGE_ITEMS})",
    )

    wave = commands.add_parser("wave", help="논리적 3-role wave 한 번 실행")
    _identity_values(wave)
    wave.add_argument("wave", choices=("discovery", "attack", "proof"))

    for name in ("pause", "resume"):
        command_parser = commands.add_parser(name)
        _identity_values(command_parser)

    budget = commands.add_parser(
        "budget-reset", help="사람의 명시적 문제 예산 초기화"
    )
    _identity_values(budget)
    budget.add_argument("--seconds", type=int, default=8 * 60 * 60)

    prove = commands.add_parser(
        "prove", help="새 clean container에서 후보 재현"
    )
    _identity_values(prove)
    prove.add_argument("--candidate", required=True)
    prove.add_argument("--input", action="append", default=[])
    prove.add_argument("--target")
    prove.add_argument("--repetitions", type=int)
    prove.add_argument("proof_command", nargs=argparse.REMAINDER)

    submit = commands.add_parser(
        "submit",
        help="flag를 표시하거나 사람이 제출한 결과만 기록",
    )
    _identity_values(submit)
    submit.add_argument("--candidate", required=True)
    submit.add_argument(
        "--outcome", choices=("accepted", "rejected", "error", "dry_run")
    )
    submit.add_argument("--response")
    submit.add_argument("--points", type=float)
    submit.add_argument("--allow-unproved", action="store_true")

    export = commands.add_parser("export", help="상태/요약을 exports에 생성")
    _identity_values(export)

    jobs = commands.add_parser("jobs", help="문제 container job 상태 조회")
    _identity_values(jobs)

    tool = commands.add_parser("tool", help="challenge-scoped sandbox 도구")
    tool_commands = tool.add_subparsers(dest="tool_command", required=True)
    tool_run = tool_commands.add_parser("run")
    _scope_options(tool_run)
    tool_run.add_argument(
        "--profile",
        choices=("light", "standard", "heavy", "gpu"),
        default="light",
    )
    tool_run.add_argument("--target")
    tool_run.add_argument(
        "--kvm",
        action="store_true",
        help="이 실행에 /dev/kvm lease와 장치 연결을 요구",
    )
    tool_run.add_argument("--timeout", type=int)
    tool_run.add_argument("--expected", default="bounded command result")
    tool_run.add_argument(
        "--keep-if", default="the result advances the active goal"
    )
    tool_run.add_argument(
        "--drop-if", default="the result is non-discriminating"
    )
    tool_run.add_argument("--hypothesis", action="append", default=[])
    tool_run.add_argument("tool_argv", nargs=argparse.REMAINDER)

    agent = commands.add_parser(
        "agent", help="Live/Batch가 쓰는 구조화 상태 제안"
    )
    agent_commands = agent.add_subparsers(
        dest="agent_command", required=True
    )

    flag = agent_commands.add_parser("flag")
    _scope_options(flag)
    flag.add_argument("value")
    flag.add_argument("--source", default="agent")
    flag.add_argument("--source-run")

    fact = agent_commands.add_parser("fact")
    _scope_options(fact)
    fact.add_argument("statement")
    fact.add_argument(
        "--provenance",
        choices=tuple(value.value for value in Provenance),
        default=Provenance.MODEL_CLAIMED.value,
    )
    fact.add_argument("--source-run")
    fact.add_argument("--artifact")
    fact.add_argument("--locator")

    experiment = agent_commands.add_parser("experiment")
    _scope_options(experiment)
    experiment.add_argument("--expected", required=True)
    experiment.add_argument("--keep-if", required=True)
    experiment.add_argument("--drop-if", required=True)
    experiment.add_argument("--hypothesis", action="append", default=[])
    experiment.add_argument(
        "--profile",
        choices=("light", "standard", "heavy", "gpu"),
        default="light",
    )
    experiment.add_argument("--timeout", type=int)
    experiment.add_argument("--target")
    experiment.add_argument(
        "--kvm",
        action="store_true",
        help="실행 시 /dev/kvm lease와 장치 연결을 요구",
    )
    experiment.add_argument("experiment_argv", nargs=argparse.REMAINDER)

    goal = agent_commands.add_parser("goal")
    _scope_options(goal)
    goal.add_argument(
        "action",
        choices=("create", "activate", "complete", "block", "park"),
    )
    goal.add_argument("--goal-id")
    goal.add_argument("--description")
    goal.add_argument("--depends-on", action="append", default=[])
    goal.add_argument("--artifact", action="append", default=[])
    goal.add_argument("--blocked-reason")
    goal.add_argument("--activate", action="store_true")

    hypothesis = agent_commands.add_parser("hypothesis")
    _scope_options(hypothesis)
    hypothesis.add_argument("action", choices=("create", "update"))
    hypothesis.add_argument("--hypothesis-id")
    hypothesis.add_argument("--statement")
    hypothesis.add_argument("--falsifier")
    hypothesis.add_argument(
        "--status",
        choices=tuple(item.value for item in HypothesisStatus),
        required=True,
    )
    hypothesis.add_argument(
        "--evidence-fact", action="append", default=[]
    )
    hypothesis.add_argument(
        "--evidence-artifact", action="append", default=[]
    )
    hypothesis.add_argument(
        "--evidence-run", action="append", default=[]
    )
    hypothesis.add_argument("--confidence", type=float)
    hypothesis.add_argument("--refuted-by")

    evaluate = agent_commands.add_parser("evaluate")
    _scope_options(evaluate)
    evaluate.add_argument("experiment_id")
    evaluate.add_argument(
        "status",
        choices=(
            ExperimentStatus.KEPT.value,
            ExperimentStatus.DROPPED.value,
            ExperimentStatus.INCONCLUSIVE.value,
            ExperimentStatus.FAILED.value,
        ),
    )
    evaluate.add_argument("--reason", required=True)
    evaluate.add_argument(
        "--evidence-fact", action="append", default=[]
    )
    evaluate.add_argument(
        "--evidence-artifact", action="append", default=[]
    )
    evaluate.add_argument(
        "--evidence-run", action="append", default=[]
    )
    evaluate.add_argument("--support", action="append", default=[])
    evaluate.add_argument("--refute", action="append", default=[])

    artifact = agent_commands.add_parser("artifact")
    _scope_options(artifact)
    artifact.add_argument("locator")
    artifact.add_argument("--source-run")

    progress = agent_commands.add_parser("progress")
    _scope_options(progress)
    progress.add_argument("statement")
    progress.add_argument("--run")
    progress.add_argument("--artifact", action="append", default=[])

    transition = agent_commands.add_parser("transition")
    _scope_options(transition)
    transition.add_argument(
        "target",
        choices=(
            "TRIAGING",
            "ACTIVE",
            "STALLED",
            "NEEDS_RESEARCH",
            "NEEDS_HUMAN",
            "PAUSED",
            "PROVING",
            "ABANDONED",
        ),
    )
    return parser


def _status_once(
    engine: ChallengeEngine, contest: str | None, *, as_json: bool
) -> None:
    if contest is not None:
        contests = [contest]
    else:
        root = engine.store.contests_root
        contests = (
            sorted(
                path.name
                for path in root.iterdir()
                if path.is_dir() and not path.is_symlink()
            )
            if root.exists()
            else []
        )
    payload: dict[str, object] = {}
    for contest_id in contests:
        payload[contest_id] = engine.store.refresh_board(contest_id)
    if as_json:
        _print_json(payload)
        return
    if not payload:
        print("등록된 대회/문제가 없습니다.")
        return
    for contest_id, raw_entries in payload.items():
        print(f"\n[{terminal_safe(contest_id)}]")
        entries = raw_entries if isinstance(raw_entries, list) else []
        for entry in entries:
            goal = entry.get("active_goal")
            goal_text = (
                str(goal.get("description", ""))
                if isinstance(goal, dict)
                else "-"
            )
            print(
                terminal_safe(
                    f"{entry['category']}/{entry['challenge_id']}: "
                    f"{entry['status']} rev={entry['revision']} "
                    f"goal={goal_text} "
                    f"candidates={len(entry['candidates'])}"
                )
            )


def _inspect_value(
    state: Any,
    section: str,
    *,
    offset: int | None = None,
    limit: int | None = None,
) -> object:
    return inspect_state(
        state,
        section,
        offset=offset,
        limit=limit,
    )


def _print_latest_tool_result(state: Any) -> None:
    if not state.experiments:
        print("실행된 experiment가 없습니다.")
        return
    experiment = state.experiments[-1]
    _print_json(
        {
            "experiment_id": experiment.id,
            "status": experiment.status.value,
            "result": experiment.result,
            "artifact_ids": experiment.artifact_ids,
        }
    )


def main(
    argv: Sequence[str] | None = None,
    *,
    root: Path | None = None,
) -> int:
    args = build_parser().parse_args(argv)
    workspace = (
        root
        if root is not None
        else args.root
        if args.root is not None
        else Path(os.environ.get("CTFOS_WORKSPACE_ROOT", Path.cwd()))
    ).expanduser().resolve()
    try:
        live_client = LiveBrokerClient.from_environment()
        if live_client is not None:
            # The attached child deliberately does not construct a local
            # engine: its Codex sandbox cannot write canonical state or access
            # Docker. All allowed effects stay in the lock-owning parent.
            return _run_live_broker_command(args, live_client)

        config = load_config(workspace)
        if args.command == "init":
            path = config.config_path
            if path.exists():
                print(f"이미 존재합니다: {path}")
                return 0
            path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write_text(path, default_config_text(), mode=0o600)
            print(f"설정 생성 완료: {path}")
            return 0

        if args.command == "pin-image":
            path = config.config_path
            if not path.is_file():
                raise CLIError(
                    "설정 파일이 없습니다. 먼저 `ctfos init`을 실행하세요."
                )
            status = inspect_local_image(config.runtime.image)
            if not image_status_is_usable(status):
                detail = status.get("error", "Docker image inspect failed")
                raise CLIError(
                    f"이미지를 고정할 수 없습니다: {config.runtime.image}: {detail}"
                )
            digest = str(status["id"])
            try:
                current_text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as error:
                raise CLIError(f"설정 파일을 읽을 수 없습니다: {error}") from error
            updated_text = set_runtime_image_digest(current_text, digest)
            if updated_text == current_text:
                print(f"이미 고정됨: {config.runtime.image} -> {digest}")
                return 0
            atomic_write_text(path, updated_text, mode=0o600)
            print(f"이미지 고정 완료: {config.runtime.image} -> {digest}")
            return 0

        if args.command == "doctor":
            report = collect_diagnostics(
                config, calibrate=args.calibrate
            )
            _print_json(report)
            return 0 if report["ok"] else 1

        if args.command == "evaluate":
            report = evaluate_workspace(
                workspace,
                contest_id=args.contest,
                category=args.category,
                challenge_id=args.challenge,
            )
            _print_json(report.to_dict())
            return 0

        engine = ChallengeEngine(workspace, config=config)

        if args.command == "init-contest":
            category, challenge = _parse_challenge_spec(args.challenge)
            state = engine.add_challenge(
                ChallengeIdentity(args.contest, category, challenge)
            )
            print(f"문제 폴더 준비 완료: {engine.challenge_input(state.identity)}")
            return 0

        if args.command == "add-challenge":
            state = engine.add_challenge(
                _identity(args),
                description=args.description,
                prompt=_prompt(args) or "",
                targets=args.target,
                budget_seconds=args.budget_seconds,
            )
            print(f"문제 폴더: {engine.challenge_input(state.identity)}")
            print(f"상태: {state.status.value} rev={state.revision}")
            return 0

        if args.command == "add-target":
            state = engine.add_network_target(
                _identity(args),
                args.target,
                docker_network=args.docker_network,
                enforcement=args.enforcement,
            )
            print(
                f"허용 대상 추가: {NetworkTarget.parse(args.target).as_text()} "
                f"(rev={state.revision})"
            )
            return 0

        if args.command == "knowledge":
            identity = _identity(args)
            store = KnowledgeStore(engine.store)
            if args.knowledge_command == "add":
                record = store.add(
                    identity,
                    args.file,
                    source_url=args.source,
                    title=args.title,
                    expected_sha256=args.sha256,
                    content_kind=args.kind,
                )
                _print_json(record.to_dict())
                return 0
            if args.knowledge_command == "list":
                _print_json(
                    [record.to_dict() for record in store.list(identity)]
                )
                return 0
            if args.knowledge_command == "search":
                _print_json(
                    [
                        {
                            "record": record.to_dict(),
                            "score": score,
                            "excerpt": excerpt,
                        }
                        for record, score, excerpt in store.search(
                            identity,
                            args.query,
                            limit=args.limit,
                        )
                    ]
                )
                return 0
            raise AssertionError(
                f"처리되지 않은 knowledge 명령: {args.knowledge_command}"
            )

        if args.command == "solve":
            identity = _identity(args)
            prompt = _prompt(args)
            paths = engine.store.challenge_paths(identity)
            state = (
                engine.store.load(identity)
                if paths.state.exists()
                else engine.add_challenge(identity)
            )
            effective_prompt = prompt if prompt else state.prompt
            if not effective_prompt.strip():
                raise CLIError(
                    "문제풀이 프롬프트가 없습니다. PROMPT 또는 --prompt-file을 "
                    "지정하세요."
                )
            def announce_live_session(_prepared: object) -> None:
                print(
                    "Live 세션 생성 완료. 세 논리 역할은 유지되며 계정 "
                    "한도에 걸린 실제 모델 호출만 대기할 수 있습니다.",
                    flush=True,
                )

            return engine.launch_live(
                identity,
                prompt=prompt if prompt else None,
                resume_thread_id=args.resume_thread,
                on_prepared=announce_live_session,
            )

        if args.command == "run-challenge":
            identity = _identity(args)
            prompt = _prompt(args)
            state = engine.run_challenge(
                identity,
                prompt=prompt if prompt else None,
                max_cycles=args.max_cycles,
                execute_registered_tools=not args.no_tools,
            )
            print(
                f"Batch 종료: {identity.key} {state.status.value} "
                f"rev={state.revision}"
            )
            return 0

        if args.command == "status":
            if not math.isfinite(args.interval) or args.interval <= 0:
                raise CLIError("--interval은 유한한 양수여야 합니다.")
            while True:
                _status_once(engine, args.contest, as_json=args.json)
                if not args.watch:
                    break
                time.sleep(args.interval)
            return 0

        if args.command == "leases":
            tool_status = engine.lease_broker.status()
            model_status = engine.batch_runner.limiter.snapshot()
            payload = {
                "tool": {
                    "capacity": tool_status.capacity.as_dict(),
                    "used": tool_status.used.as_dict(),
                    "available": tool_status.available.as_dict(),
                    "queued": tool_status.queued,
                    "leases": [
                        {
                            "id": lease.lease_id,
                            "owner": lease.owner,
                            "resources": lease.resources.as_dict(),
                        }
                        for lease in tool_status.leases
                    ],
                },
                "provider_model_calls": {
                    "capacity": model_status.capacity,
                    "active": model_status.active,
                    "waiting": model_status.waiting,
                    "logical_wave_width": 3,
                    "note": "waiting never removes a logical role",
                },
            }
            _print_json(payload)
            return 0

        if args.command == "inspect":
            state = engine.store.load(_identity(args))
            _print_json(
                _inspect_value(
                    state,
                    args.section,
                    offset=args.offset,
                    limit=args.limit,
                )
            )
            return 0

        if args.command == "wave":
            outcome = engine.run_wave(_identity(args), args.wave)
            _print_json(
                {
                    "wave": outcome.wave,
                    "logical_roles": [
                        result.invocation.role.value
                        for result in outcome.results
                    ],
                    "success": [
                        result.success for result in outcome.results
                    ],
                    "base_revision": outcome.base_revision,
                    "committed_revision": outcome.committed_revision,
                    "candidate_values": outcome.candidate_values,
                }
            )
            return 0

        if args.command == "pause":
            state = engine.pause(_identity(args))
            print(
                f"PAUSED (resume={state.resume_status.value if state.resume_status else '-'})"
            )
            return 0

        if args.command == "resume":
            state = engine.resume(_identity(args))
            print(f"재개: {state.status.value}")
            return 0

        if args.command == "budget-reset":
            state = engine.reset_budget(_identity(args), args.seconds)
            print(
                f"예산 초기화: {state.budget.allocated_seconds}s "
                f"spent={state.budget.spent_seconds}s"
            )
            return 0

        if args.command == "prove":
            command = _strip_remainder(args.proof_command)
            state, result = engine.prove_candidate(
                _identity(args),
                args.candidate,
                command,
                input_locators=args.input,
                network_target=args.target,
                repetitions=args.repetitions,
            )
            _print_json(result.to_dict())
            return 0 if result.passed else 1

        if args.command == "submit":
            identity = _identity(args)
            candidate = engine.submission_preview(
                identity, args.candidate
            )
            if args.outcome is None:
                print(
                    "CTF 사이트에는 사람이 직접 제출하세요. 결과 확인 후 "
                    f"`ctfos submit ... --candidate {candidate.id} "
                    "--outcome accepted|rejected`로 기록합니다."
                )
                return 0
            state = engine.record_manual_submission(
                identity,
                args.candidate,
                outcome=args.outcome,
                response=args.response,
                points=args.points,
                allow_unproved=args.allow_unproved,
            )
            print(
                f"사람 제출 결과 기록 완료: {args.outcome}; "
                f"state={state.status.value}"
            )
            return 0

        if args.command == "export":
            identity = _identity(args)
            state = engine.store.load(identity)
            paths = engine.store.challenge_paths(identity)
            engine.store.refresh_views(identity)
            atomic_write_json(paths.exports / "state.json", state.to_dict())
            atomic_write_text(
                paths.exports / "summary.md",
                paths.current_context.read_text(encoding="utf-8"),
            )
            print(f"export 완료: {paths.exports}")
            return 0

        if args.command == "jobs":
            identity = _identity(args)
            _verify_session_scope(identity, engine)
            state = engine.run_tool_command(
                identity,
                ("ctf-jobs", "--json"),
                expected_observation="bounded background job list",
                keep_if="a running/completed job changes the active goal",
                drop_if="there are no relevant jobs",
            )
            _print_latest_tool_result(state)
            return 0

        if args.command == "tool":
            identity = _scoped_identity(args, engine)
            command = _strip_remainder(args.tool_argv)
            state = engine.run_tool_command(
                identity,
                command,
                expected_observation=args.expected,
                keep_if=args.keep_if,
                drop_if=args.drop_if,
                hypothesis_ids=args.hypothesis,
                timeout_seconds=args.timeout,
                resource_class=args.profile,
                network_target=args.target,
                needs_kvm=args.kvm,
            )
            _print_latest_tool_result(state)
            return 0

        if args.command == "agent":
            identity = _scoped_identity(args, engine)
            if args.agent_command == "flag":
                state = engine.record_candidate(
                    identity,
                    args.value,
                    source=args.source,
                    source_run_id=args.source_run,
                )
                candidate = next(
                    item
                    for item in state.candidates
                    if item.value == args.value
                )
                print(f"candidate 기록: {candidate.id}")
                return 0
            if args.agent_command == "fact":
                state = engine.record_fact(
                    identity,
                    args.statement,
                    provenance=Provenance(args.provenance),
                    source_run_id=args.source_run,
                    artifact_id=args.artifact,
                    locator=args.locator,
                )
                print(f"fact 기록: {state.facts[-1].id}")
                return 0
            if args.agent_command == "experiment":
                command = _strip_remainder(args.experiment_argv)
                _state, experiment_id = engine.register_experiment(
                    identity,
                    command=command,
                    expected_observation=args.expected,
                    keep_if=args.keep_if,
                    drop_if=args.drop_if,
                    hypothesis_ids=args.hypothesis,
                    timeout_seconds=args.timeout,
                    resource_class=args.profile,
                    network_target=args.target,
                    needs_kvm=args.kvm,
                )
                print(f"experiment 사전 등록: {experiment_id}")
                return 0
            if args.agent_command == "goal":
                state, goal_id = engine.manage_goal(
                    identity,
                    action=args.action,
                    goal_id=args.goal_id,
                    description=args.description,
                    depends_on=args.depends_on,
                    artifact_ids=args.artifact,
                    blocked_reason=args.blocked_reason,
                    activate=args.activate,
                )
                goal = next(
                    item for item in state.goals if item.id == goal_id
                )
                print(
                    f"goal 갱신: {goal_id} status={goal.status.value} "
                    f"active={state.active_goal_id or '-'}"
                )
                return 0
            if args.agent_command == "hypothesis":
                state, hypothesis_id = engine.manage_hypothesis(
                    identity,
                    action=args.action,
                    hypothesis_id=args.hypothesis_id,
                    statement=args.statement,
                    falsifier=args.falsifier,
                    status=HypothesisStatus(args.status),
                    evidence_fact_ids=args.evidence_fact,
                    evidence_artifact_ids=args.evidence_artifact,
                    evidence_run_ids=args.evidence_run,
                    confidence=args.confidence,
                    refuted_by=args.refuted_by,
                )
                hypothesis = next(
                    item
                    for item in state.hypotheses
                    if item.id == hypothesis_id
                )
                print(
                    f"hypothesis 갱신: {hypothesis_id} "
                    f"status={hypothesis.status.value}"
                )
                return 0
            if args.agent_command == "evaluate":
                state = engine.evaluate_experiment(
                    identity,
                    args.experiment_id,
                    status=ExperimentStatus(args.status),
                    reason=args.reason,
                    evidence_fact_ids=args.evidence_fact,
                    evidence_artifact_ids=args.evidence_artifact,
                    evidence_run_ids=args.evidence_run,
                    support_hypothesis_ids=args.support,
                    refute_hypothesis_ids=args.refute,
                )
                experiment = next(
                    item
                    for item in state.experiments
                    if item.id == args.experiment_id
                )
                print(
                    f"experiment 평가: {experiment.id} "
                    f"status={experiment.status.value}"
                )
                return 0
            if args.agent_command == "artifact":
                _state, artifact = engine.register_workspace_artifact(
                    identity,
                    args.locator,
                    source_run_id=args.source_run,
                )
                print(f"artifact 등록: {artifact.id} sha256={artifact.sha256}")
                return 0
            if args.agent_command == "progress":
                state = engine.mark_progress(
                    identity,
                    args.statement,
                    run_id=args.run,
                    artifact_ids=args.artifact,
                )
                print(f"progress 기록: {state.progress_markers[-1].id}")
                return 0
            if args.agent_command == "transition":
                state = engine.transition(
                    identity, ChallengeStatus(args.target)
                )
                print(f"transition: {state.status.value}")
                return 0

        raise AssertionError(f"처리되지 않은 명령: {args.command}")
    except KeyboardInterrupt:
        print("\n중단됨", file=sys.stderr)
        return 130
    except (
        CLIError,
        ConfigError,
        EngineError,
        EvaluationError,
        SessionAlreadyRunning,
        StateStoreError,
        KnowledgeError,
        LiveBrokerError,
        SandboxError,
        ValueError,
        OSError,
    ) as error:
        exit_code = error.exit_code if isinstance(error, CLIError) else 2
        print(f"오류: {terminal_safe(error)}", file=sys.stderr)
        return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
