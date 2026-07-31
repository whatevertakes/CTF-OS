"""Operator and agent CLI for the challenge-scoped CTF-OS engine."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import stat
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from ctf_os.benchmark import (
    THIN_SCAFFOLD,
    BlindLivePromotionEvidence,
    evaluate_blind_live_promotion,
)
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
from ctf_os.engine.rev_runtime_proof import (
    RevRuntimeProofError,
    prove_rev_runtime_accepted_input,
)
from ctf_os.evaluation import EvaluationError, evaluate_workspace
from ctf_os.images import image_status_is_usable, inspect_local_image
from ctf_os.knowledge import KnowledgeError, KnowledgeStore
from ctf_os.lifecycle import (
    close_challenge,
    create_checkpoint,
    export_challenge,
    pause_with_handoff,
)
from ctf_os.live_broker import (
    INSPECT_SECTIONS,
    LIVE_SCOPE_CAPABILITY_ENV,
    MAX_INSPECT_OFFSET,
    MAX_INSPECT_PAGE_ITEMS,
    LiveBrokerClient,
    LiveBrokerError,
    inspect_state,
)
from ctf_os.managed import (
    ManagedError,
    ManagedOrchestrator,
    ManagedPreflightBlocked,
)
from ctf_os.migration import (
    MigrationError,
    apply_migration,
    plan_migration,
    rollback_migration,
)
from ctf_os.models import (
    ChallengeIdentity,
    ChallengeStatus,
    ExperimentStatus,
    HypothesisStatus,
    Provenance,
)
from ctf_os.nyu_stage import stage_nyu_ctf_bench
from ctf_os.promotion_bundles import (
    capture_promotion_session,
    evaluate_promotion_bundles,
    execution_fingerprint_report,
    finalize_promotion_session,
    freeze_promotion_manifest,
    prepare_promotion_session,
)
from ctf_os.sandbox import JobRef, NetworkTarget, SandboxError
from ctf_os.scaffold_binding import (
    ScaffoldBindingError,
    solve_mode_arm,
)
from ctf_os.schema import STATE_SCHEMA_VERSION
from ctf_os.storage import (
    StorageError,
    prepare_quarantine_purge,
    purge_quarantine,
    quarantine_unreachable,
    restore_quarantine,
    storage_inventory,
    storage_plan,
)
from ctf_os.store import StateStoreError
from ctf_os.store.atomic import atomic_write_text, strict_json_loads
from ctf_os.terminal import terminal_safe


class CLIError(RuntimeError):
    def __init__(self, message: str, exit_code: int = 2) -> None:
        super().__init__(message)
        self.exit_code = exit_code


MAX_PROMOTION_EVIDENCE_BYTES = 16 * 1024 * 1024


def _rev_runtime_timeout_argument(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "Rev runtime timeout must be an integer"
        ) from error
    if not 1 <= parsed <= 3600:
        raise argparse.ArgumentTypeError(
            "Rev runtime timeout must be between 1 and 3600 seconds"
        )
    return parsed


def _read_bounded_regular_bytes(
    path: Path,
    *,
    maximum: int,
    label: str,
) -> bytes:
    """Read one stable regular file without following its terminal symlink."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise CLIError(f"{label} 파일을 안전하게 열 수 없습니다.") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise CLIError(f"{label} 입력은 일반 파일이어야 합니다.")
        if before.st_size > maximum:
            raise CLIError(f"{label} 파일은 {maximum} bytes 이하여야 합니다.")

        chunks = bytearray()
        while len(chunks) <= maximum:
            block = os.read(
                descriptor,
                min(1024 * 1024, maximum + 1 - len(chunks)),
            )
            if not block:
                break
            chunks.extend(block)
        if len(chunks) > maximum:
            raise CLIError(f"{label} 파일은 {maximum} bytes 이하여야 합니다.")

        after = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_identity != after_identity or len(chunks) != after.st_size:
            raise CLIError(f"{label} 파일이 읽는 동안 변경되었습니다.")
        return bytes(chunks)
    except OSError as error:
        raise CLIError(f"{label} 파일을 안전하게 읽을 수 없습니다.") from error
    finally:
        os.close(descriptor)


def _read_rev_runtime_expected_oracle(path: Path) -> dict[str, object]:
    """Read one canonical hash/size-only oracle without exposing its path."""

    from ctf_os.engine.rev_acceptance import (
        REV_ACCEPTANCE_MAX_SPEC_BYTES,
        RevAcceptanceContractError,
        canonical_json_bytes,
        validate_rev_acceptance_expected_oracle,
    )
    from ctf_os.store.atomic import StrictJSONError

    payload = _read_bounded_regular_bytes(
        path,
        maximum=REV_ACCEPTANCE_MAX_SPEC_BYTES,
        label="Rev runtime hash-only oracle",
    )
    try:
        value = strict_json_loads(
            payload,
            max_bytes=REV_ACCEPTANCE_MAX_SPEC_BYTES,
        )
        normalized = validate_rev_acceptance_expected_oracle(value)
        if payload != canonical_json_bytes(normalized):
            raise CLIError(
                "Rev runtime hash-only oracle JSON은 canonical 형식이어야 "
                "합니다."
            )
    except CLIError:
        raise
    except (
        RevAcceptanceContractError,
        StrictJSONError,
        TypeError,
        ValueError,
    ) as error:
        raise CLIError(
            "Rev runtime hash-only oracle JSON이 유효하지 않습니다."
        ) from error
    return normalized


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


def _flag_format_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--flag-prefix",
        help="이 문제의 exact prefix-brace flag 형식",
    )
    parser.add_argument(
        "--contest-flag-prefix",
        help="첫 문제 생성 전에 고정할 대회 공통 prefix-brace 형식",
    )
    parser.add_argument(
        "--flag-alphabet",
        choices=("printable", "alnum_", "hex", "base64url"),
    )
    parser.add_argument("--flag-min-inner", type=int)
    parser.add_argument("--flag-max-inner", type=int)


def _flag_formats(
    args: argparse.Namespace,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    challenge_prefix = getattr(args, "flag_prefix", None)
    contest_prefix = getattr(args, "contest_flag_prefix", None)
    alphabet = getattr(args, "flag_alphabet", None)
    minimum = getattr(args, "flag_min_inner", None)
    maximum = getattr(args, "flag_max_inner", None)
    if (
        challenge_prefix is None
        and contest_prefix is None
        and any(value is not None for value in (alphabet, minimum, maximum))
    ):
        raise CLIError(
            "flag alphabet/bounds require --flag-prefix or "
            "--contest-flag-prefix"
        )

    def record(prefix: str | None) -> dict[str, Any] | None:
        if prefix is None:
            return None
        return {
            "kind": "prefix_brace",
            "prefix": prefix,
            "alphabet": alphabet or "printable",
            "min_inner": 1 if minimum is None else minimum,
            "max_inner": 512 if maximum is None else maximum,
        }

    return record(challenge_prefix), record(contest_prefix)


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


def _effective_thread_continuity(args: argparse.Namespace) -> str:
    """Resolve CLI-only continuity defaults without changing the API default."""

    selected = args.thread_continuity
    if selected is not None:
        return selected
    if (
        args.command == "managed-cycle"
        or getattr(args, "mode", None) == "managed"
    ):
        return "captain_lane"
    return "fresh"


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
    state = engine.store.read_snapshot(identity)
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
        params: dict[str, object] = {
            "runtime_id": args.runtime_id,
            "tail_bytes": args.tail_bytes,
            "grace_seconds": args.grace,
        }
        if args.job_id is not None:
            params["job_id"] = args.job_id
        if args.supervisor_id is not None:
            params["supervisor_id"] = args.supervisor_id
        if args.log:
            params["action"] = "log"
        elif args.cancel:
            params["action"] = "cancel"
        elif args.job_id is not None:
            params["action"] = "status"
        else:
            params["action"] = "recover" if args.recover else "list"
        result = _broker_dict(client.call("jobs", identity, params))
        _print_json(result)
        return 0

    if args.command == "tool":
        command = _strip_remainder(args.tool_argv)
        if args.tool_command == "start":
            result = _broker_dict(
                client.call(
                    "tool.start",
                    identity,
                    {
                        "command": list(command),
                        "name": args.name,
                        "timeout_seconds": args.timeout,
                        "resource_class": args.profile,
                        "network_target": args.target,
                        "needs_kvm": args.kvm,
                    },
                )
            )
            _print_json(result)
            return 0
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
                    "read_only": args.read_only,
                    "input_locators": list(args.input),
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
    _flag_format_options(init_contest)

    add = commands.add_parser(
        "add-challenge", help="사람이 파일을 넣을 문제 폴더와 상태 생성"
    )
    _identity_values(add)
    add.add_argument("--description", default="")
    add.add_argument("--prompt")
    add.add_argument("--prompt-file", type=Path)
    add.add_argument("--target", action="append", default=[])
    add_budget = add.add_mutually_exclusive_group()
    add_budget.add_argument("--budget-seconds", type=int)
    add_budget.add_argument("--unbounded", action="store_true")
    add.add_argument("--reason")
    _flag_format_options(add)

    target = commands.add_parser(
        "add-target", help="문제별 허용 원격 endpoint 추가"
    )
    _identity_values(target)
    target.add_argument("target")
    target.add_argument("--docker-network", default="bridge")
    target.add_argument(
        "--enforcement",
        choices=("declared", "proxy", "builtin"),
        default="declared",
    )
    target.add_argument("--http-rate", type=float, default=2.0)
    target.add_argument("--http-burst", type=int, default=4)

    typed_target = commands.add_parser(
        "target", help="typed challenge target lifecycle"
    )
    typed_target_commands = typed_target.add_subparsers(
        dest="target_command", required=True
    )
    target_list = typed_target_commands.add_parser("list")
    _identity_values(target_list)
    target_add = typed_target_commands.add_parser("add")
    _identity_values(target_add)
    target_add.add_argument("endpoint")
    target_add.add_argument("--purpose", default="challenge remote")
    target_add.add_argument("--docker-network", default="bridge")
    target_add.add_argument(
        "--enforcement",
        choices=("declared", "proxy", "builtin"),
        default="declared",
    )
    target_add.add_argument("--http-rate", type=float, default=2.0)
    target_add.add_argument("--http-burst", type=int, default=4)
    target_add.add_argument("--expires-at")
    target_select = typed_target_commands.add_parser("select")
    _identity_values(target_select)
    target_select.add_argument("target_id")
    target_check = typed_target_commands.add_parser("check")
    _identity_values(target_check)
    target_check.add_argument("target_id")
    target_smoke = typed_target_commands.add_parser(
        "smoke",
        help="built-in boundary를 통한 명시적 원격 preflight",
    )
    _identity_values(target_smoke)
    target_smoke.add_argument("target_id")
    target_smoke.add_argument(
        "--mode",
        action="append",
        choices=("dns", "tcp", "tls", "websocket"),
        required=True,
    )
    target_smoke.add_argument("--path", default="/")
    target_smoke.add_argument("--timeout", type=int, default=10)
    target_replace = typed_target_commands.add_parser("replace")
    _identity_values(target_replace)
    target_replace.add_argument("target_id")
    target_replace.add_argument("endpoint")
    target_replace.add_argument("--reason", required=True)
    target_replace.add_argument("--purpose", default="challenge remote")
    target_replace.add_argument("--expires-at")
    target_revoke = typed_target_commands.add_parser("revoke")
    _identity_values(target_revoke)
    target_revoke.add_argument("target_id")
    target_revoke.add_argument("--reason", required=True)

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
    solve.add_argument(
        "--mode",
        choices=("managed", "assisted", "thin"),
        default="assisted",
    )
    solve.add_argument("--max-cycles", type=int, default=8)
    solve.add_argument(
        "--thread-continuity",
        "--thread-continuity-policy",
        dest="thread_continuity",
        choices=("fresh", "captain_lane", "role_lane"),
        default=None,
        help=(
            "managed session model-thread policy; pinned before the first "
            "cycle (omitted: captain_lane in managed mode, fresh otherwise)"
        ),
    )

    preflight = commands.add_parser(
        "preflight", help="managed solve prerequisites"
    )
    _identity_values(preflight)
    preflight.add_argument("--json", action="store_true")

    managed_cycle = commands.add_parser(
        "managed-cycle", help="run one durable managed cycle"
    )
    _identity_values(managed_cycle)
    managed_cycle.add_argument("--session-id")
    managed_cycle.add_argument(
        "--thread-continuity",
        "--thread-continuity-policy",
        dest="thread_continuity",
        choices=("fresh", "captain_lane", "role_lane"),
        default=None,
        help="model-thread policy (omitted: captain_lane)",
    )
    note_group = managed_cycle.add_mutually_exclusive_group()
    note_group.add_argument("--note")
    note_group.add_argument("--note-file", type=Path)
    managed_cycle.add_argument("--json", action="store_true")

    run = commands.add_parser(
        "run-challenge", help="결정적 Captain/3-role Batch 실행"
    )
    _identity_values(run)
    run.add_argument("--prompt")
    run.add_argument("--prompt-file", type=Path)
    run.add_argument("--max-cycles", type=int, default=8)
    run.add_argument("--no-tools", action="store_true")
    run.add_argument(
        "--mode", choices=("managed", "legacy"), default="legacy"
    )
    run.add_argument(
        "--thread-continuity",
        "--thread-continuity-policy",
        dest="thread_continuity",
        choices=("fresh", "captain_lane", "role_lane"),
        default=None,
        help=(
            "managed model-thread policy "
            "(omitted: captain_lane in managed mode, fresh otherwise)"
        ),
    )

    session = commands.add_parser("session", help="managed session control")
    session_commands = session.add_subparsers(
        dest="session_command", required=True
    )
    session_cancel = session_commands.add_parser("cancel")
    _identity_values(session_cancel)
    session_cancel.add_argument("--reason", required=True)
    session_cancel.add_argument(
        "--target",
        choices=("PAUSED", "NEEDS_HUMAN"),
        required=True,
    )

    migrate = commands.add_parser("migrate", help="explicit state migration")
    migrate.add_argument(
        "migration_command",
        choices=("check", "plan", "apply", "rollback"),
    )
    migrate.add_argument("--id", default="state-v2")

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

    benchmark = commands.add_parser(
        "benchmark",
        help="operator-supplied benchmark evidence의 읽기 전용 gate 평가",
    )
    benchmark_commands = benchmark.add_subparsers(
        dest="benchmark_command",
        required=True,
    )
    promotion = benchmark_commands.add_parser(
        "promotion",
        help="blind/live promotion evidence를 fail-closed로 평가",
    )
    promotion.add_argument(
        "--evidence",
        type=Path,
        required=True,
        help="strict JSON promotion evidence 파일(자동 승격에는 사용하지 않음)",
    )
    promotion_freeze = benchmark_commands.add_parser(
        "freeze",
        help="paired challenge/session manifest를 실행 전에 고정",
    )
    promotion_freeze.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="strict pre-run session manifest",
    )
    promotion_freeze.add_argument(
        "--output",
        type=Path,
        required=True,
        help="새 frozen manifest 출력(기존 경로는 덮어쓰지 않음)",
    )
    promotion_capture = benchmark_commands.add_parser(
        "capture",
        help="사람이 연 정확히 한 challenge session을 evidence bundle로 캡처",
    )
    promotion_capture.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="ctfos benchmark freeze 출력",
    )
    promotion_capture.add_argument(
        "--session",
        required=True,
        help="frozen manifest의 exact session_id",
    )
    promotion_capture.add_argument(
        "--output",
        type=Path,
        required=True,
        help="새 bundle directory(기존 경로는 덮어쓰지 않음)",
    )
    promotion_compare = benchmark_commands.add_parser(
        "compare",
        help="signed bundles를 재검증해 thin baseline과 CTF-OS를 비교",
    )
    promotion_compare.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="ctfos benchmark freeze 출력",
    )
    promotion_compare.add_argument(
        "--bundle",
        type=Path,
        action="append",
        default=[],
        help="capture bundle directory; 모든 고정 session에 대해 반복",
    )
    benchmark_commands.add_parser(
        "fingerprint",
        help="현재 단일-model/tool/image 실행 fingerprint 출력",
    )
    promotion_prepare = benchmark_commands.add_parser(
        "prepare",
        help="아직 실행하지 않은 한 challenge state를 frozen session에 결속",
    )
    promotion_prepare.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="ctfos benchmark freeze 출력",
    )
    promotion_prepare.add_argument(
        "--session",
        required=True,
        help="frozen manifest의 exact session_id",
    )
    promotion_finalize = benchmark_commands.add_parser(
        "finalize",
        help="capture 전에 사람 개입·leak counter를 명시적으로 확정",
    )
    promotion_finalize.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="ctfos benchmark freeze 출력",
    )
    promotion_finalize.add_argument(
        "--session",
        required=True,
        help="frozen manifest의 exact session_id",
    )
    promotion_finalize.add_argument(
        "--human-interventions",
        type=int,
        required=True,
    )
    promotion_finalize.add_argument(
        "--secret-or-flag-leaks",
        type=int,
        required=True,
    )
    nyu_stage = benchmark_commands.add_parser(
        "nyu-stage",
        help=(
            "operator가 고른 NYU CTF Bench 전-category partial cohort를 "
            "실행 없이 staging"
        ),
    )
    nyu_stage.add_argument(
        "--source",
        type=Path,
        required=True,
        help="operator가 pin/checkout한 NYU CTF Bench repository",
    )
    nyu_stage.add_argument(
        "--release-commit",
        required=True,
        help="checkout HEAD와 정확히 같아야 하는 full Git object ID",
    )
    nyu_stage.add_argument(
        "--case",
        dest="cases",
        action="append",
        required=True,
        help=(
            "test_dataset.json의 canonical case ID; 자동 선택 없이 반복 지정"
        ),
    )
    nyu_stage.add_argument(
        "--output-manifest",
        type=Path,
        required=True,
        help="새 schema-v2 partial manifest(기존 파일 덮어쓰기 금지)",
    )
    nyu_stage.add_argument("--contest", required=True)
    nyu_stage.add_argument(
        "--split",
        choices=("dev", "regression", "blind", "live", "hidden"),
        required=True,
    )
    nyu_stage.add_argument(
        "--budget-wall-seconds",
        "--wall-seconds",
        dest="budget_wall_seconds",
        type=int,
        required=True,
    )
    nyu_stage.add_argument(
        "--budget-model-calls",
        "--model-call-limit",
        dest="budget_model_calls",
        type=int,
        required=True,
    )
    nyu_stage.add_argument(
        "--budget-tokens",
        "--total-token-limit",
        dest="budget_tokens",
        type=int,
        required=True,
    )

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

    pause = commands.add_parser("pause")
    _identity_values(pause)
    pause.add_argument("--handoff", type=Path)
    resume = commands.add_parser("resume")
    _identity_values(resume)

    checkpoint = commands.add_parser("checkpoint")
    _identity_values(checkpoint)
    checkpoint.add_argument("--note")

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

    pwn_effect = commands.add_parser(
        "pwn-prove-effect",
        help=(
            "검증된 RIP-control 부모와 정적 payload를 사전 발행한 뒤 "
            "network-denied 원본 3회 + control 3회로 exploit effect 검증"
        ),
    )
    _identity_values(pwn_effect)
    pwn_effect.add_argument(
        "--parent",
        required=True,
        help="완료된 Pwn instruction-pointer-control experiment ID",
    )
    pwn_effect.add_argument(
        "--payload",
        required=True,
        help="challenge workspace 안의 정적 exploit payload locator",
    )
    pwn_effect.add_argument("--timeout", type=int, default=300)

    pwn_interaction = commands.add_parser(
        "pwn-prove-interaction",
        help=(
            "실행 증거 부모와 bounded data-only recipe를 결속해 "
            "network-denied 원본 3회 + producer control 3회로 동적 "
            "exploit effect 검증"
        ),
    )
    _identity_values(pwn_interaction)
    pwn_interaction.add_argument(
        "--parent",
        required=True,
        help=(
            "typed RIP-control 또는 canonical executed parent "
            "experiment ID"
        ),
    )
    pwn_interaction.add_argument(
        "--recipe",
        required=True,
        help="challenge workspace 안의 canonical interaction recipe",
    )
    pwn_interaction.add_argument("--timeout", type=int, default=900)

    web_prove = commands.add_parser(
        "web-prove",
        help=(
            "운영자 Web impact spec/driver를 사전 발행한 뒤 "
            "격리된 3회 replay로 실행 검증"
        ),
    )
    _identity_values(web_prove)
    web_prove.add_argument("--spec", required=True)
    web_prove.add_argument("--driver", required=True)
    web_prove.add_argument(
        "--hypothesis",
        action="append",
        default=[],
    )
    web_prove.add_argument("--timeout", type=int, default=900)

    web_active = commands.add_parser(
        "web-prove-active",
        help=(
            "운영자 Web race/OOB spec과 concrete driver를 사전 발행한 "
            "뒤 vulnerable 3회 + control 3회로 실행 검증"
        ),
    )
    _identity_values(web_active)
    web_active.add_argument("--spec", required=True)
    web_active.add_argument("--driver", required=True)
    web_active.add_argument(
        "--hypothesis",
        action="append",
        default=[],
    )
    web_active.add_argument("--timeout", type=int, default=900)

    web_active_query = commands.add_parser(
        "web-active-query",
        help="저장된 Web race/OOB 증거를 원본 byte에서 다시 검증",
    )
    _identity_values(web_active_query)
    web_active_query.add_argument("--attempt")

    forensic_prove = commands.add_parser(
        "forensic-prove",
        help=(
            "운영자 assertion spec을 증거 index와 결속하고 독립 tool "
            "family의 격리 실행으로 교차 검증"
        ),
    )
    _identity_values(forensic_prove)
    forensic_prove.add_argument("--spec", required=True)
    forensic_prove.add_argument(
        "--hypothesis",
        action="append",
        default=[],
    )
    forensic_prove.add_argument("--timeout", type=int, default=900)

    rev_accept = commands.add_parser(
        "rev-prove-accept",
        help=(
            "운영자 hash-only oracle spec을 원본 바이너리와 결속하고 "
            "accepted input 3회 + 고정 변형 3회로 검증"
        ),
    )
    _identity_values(rev_accept)
    rev_accept.add_argument("--spec", required=True)
    rev_accept.add_argument("--timeout", type=int, default=300)

    rev_runtime = commands.add_parser(
        "rev-prove-runtime",
        help=(
            "canonical runtime spec과 hash-only oracle를 결속해 "
            "PE/JVM/.NET/WASM/native/QEMU accepted input을 "
            "3회 + 고정 변형 3회로 검증"
        ),
    )
    _identity_values(rev_runtime)
    rev_runtime.add_argument(
        "--runtime-spec",
        required=True,
        help="challenge workspace 안의 canonical runtime spec locator",
    )
    rev_runtime.add_argument(
        "--accepted-input-file",
        type=Path,
        required=True,
        help=(
            "CTF-OS workspace 전체 밖의 operator-private regular file"
        ),
    )
    rev_runtime.add_argument(
        "--oracle",
        type=Path,
        required=True,
        help="canonical hash/size-only expected oracle JSON file",
    )
    rev_runtime.add_argument(
        "--timeout",
        type=_rev_runtime_timeout_argument,
        default=300,
    )

    crypto_preissue = commands.add_parser(
        "managed-oracle-preissue-crypto",
        aliases=["oracle-preissue-crypto"],
        help=(
            "managed Builder 시작 전에 Crypto variant와 expected output을 "
            "engine-private one-shot oracle로 봉인"
        ),
    )
    _identity_values(crypto_preissue)
    crypto_preissue.add_argument("--variant-parameters", required=True)
    crypto_preissue.add_argument(
        "--variant-expected-output",
        required=True,
    )
    crypto_preissue.add_argument("--mutation-id", required=True)

    misc_preissue = commands.add_parser(
        "managed-oracle-preissue-misc",
        aliases=["oracle-preissue-misc"],
        help=(
            "managed Builder 시작 전에 Misc verifier와 oracle id를 "
            "engine-private one-shot oracle로 봉인"
        ),
    )
    _identity_values(misc_preissue)
    misc_preissue.add_argument("--verifier", required=True)
    misc_preissue.add_argument("--verifier-id", required=True)
    misc_preissue.add_argument("--oracle-id", required=True)

    crypto_transcript_preissue = commands.add_parser(
        "managed-oracle-preissue-crypto-transcript",
        aliases=["oracle-preissue-crypto-transcript"],
        help=(
            "managed Builder 시작 전에 Crypto interactive peer와 초기 "
            "data를 engine-private one-shot transcript oracle로 봉인"
        ),
    )
    _identity_values(crypto_transcript_preissue)
    crypto_transcript_preissue.add_argument("--peer", required=True)
    crypto_transcript_preissue.add_argument("--peer-data", required=True)

    misc_transcript_preissue = commands.add_parser(
        "managed-oracle-preissue-misc-transcript",
        aliases=["oracle-preissue-misc-transcript"],
        help=(
            "managed Builder 시작 전에 Misc interactive peer와 초기 "
            "data를 engine-private one-shot transcript oracle로 봉인"
        ),
    )
    _identity_values(misc_transcript_preissue)
    misc_transcript_preissue.add_argument("--peer", required=True)
    misc_transcript_preissue.add_argument("--peer-data", required=True)

    crypto_prove = commands.add_parser(
        "crypto-prove",
        help=(
            "운영자가 제공한 독립 variant oracle로 고정 solver를 "
            "원본 3회 + 변경 파라미터 3회 검증"
        ),
    )
    _identity_values(crypto_prove)
    crypto_prove.add_argument("--candidate", required=True)
    crypto_prove.add_argument("--solver", required=True)
    crypto_prove.add_argument("--original-parameters", required=True)
    crypto_prove.add_argument("--variant-parameters", required=True)
    crypto_prove.add_argument("--variant-expected-output", required=True)
    crypto_prove.add_argument("--mutation-id", required=True)
    crypto_prove.add_argument(
        "--runtime",
        choices=("python", "sage"),
        default="python",
    )

    misc_prove = commands.add_parser(
        "misc-prove",
        help=(
            "운영자 JSON DAG의 변환과 original-condition oracle를 "
            "network-denied clean sandbox에서 실행 (flag proof/제출 아님)"
        ),
    )
    _identity_values(misc_prove)
    misc_prove.add_argument("--candidate", required=True)
    misc_prove.add_argument("--spec", required=True)

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
    submit.add_argument("--override-reason")

    export = commands.add_parser("export", help="상태/요약을 exports에 생성")
    _identity_values(export)
    export.add_argument("--closure", action="store_true")
    export.add_argument("--redacted", action="store_true")

    close = commands.add_parser("close", help="record closure bundle")
    _identity_values(close)
    close.add_argument(
        "--portability",
        choices=("portable", "referential"),
        default="referential",
    )

    storage = commands.add_parser(
        "storage", help="artifact reachability and quarantine"
    )
    storage_commands = storage.add_subparsers(
        dest="storage_command", required=True
    )
    for storage_name in (
        "inventory",
        "plan",
        "gc",
        "restore",
        "purge-prepare",
        "purge",
    ):
        storage_parser = storage_commands.add_parser(storage_name)
        _identity_values(storage_parser)
        if storage_name in {"restore", "purge-prepare", "purge"}:
            storage_parser.add_argument("quarantine_id")
        if storage_name == "purge":
            storage_parser.add_argument("--manifest-sha256", required=True)
            storage_parser.add_argument(
                "--confirm",
                required=True,
                help="purge-prepare가 출력한 confirmation을 정확히 다시 입력",
            )

    gc = commands.add_parser(
        "gc",
        help="도달 불가능 artifact를 가역 quarantine으로만 이동",
    )
    _identity_values(gc)

    jobs = commands.add_parser("jobs", help="문제 container job 상태 조회")
    _identity_values(jobs)
    jobs.add_argument("--job-id")
    jobs.add_argument("--supervisor-id")
    jobs.add_argument("--runtime-id", default="none")
    jobs.add_argument("--log", action="store_true")
    jobs.add_argument("--cancel", action="store_true")
    jobs.add_argument("--recover", action="store_true")
    jobs.add_argument("--tail-bytes", type=int, default=8192)
    jobs.add_argument("--grace", type=int, default=3)

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
    tool_run.add_argument(
        "--read-only",
        action="store_true",
        help=(
            "standalone operator mode에서 명시 입력만 private work tree로 "
            "복사해 동시 분석"
        ),
    )
    tool_run.add_argument(
        "--input",
        action="append",
        default=[],
        metavar="LOCATOR",
        help=(
            "--read-only 분석에 복사할 canonical workspace 상대 경로 "
            "(반복 가능)"
        ),
    )
    tool_run.add_argument("--expected", default="bounded command result")
    tool_run.add_argument(
        "--keep-if", default="the result advances the active goal"
    )
    tool_run.add_argument(
        "--drop-if", default="the result is non-discriminating"
    )
    tool_run.add_argument("--hypothesis", action="append", default=[])
    tool_run.add_argument("tool_argv", nargs=argparse.REMAINDER)
    tool_start = tool_commands.add_parser(
        "start",
        help="lease-bound challenge background job 시작",
    )
    _scope_options(tool_start)
    tool_start.add_argument(
        "--profile",
        choices=("light", "standard", "heavy", "gpu"),
        default="light",
    )
    tool_start.add_argument("--target")
    tool_start.add_argument("--kvm", action="store_true")
    tool_start.add_argument("--timeout", type=int)
    tool_start.add_argument("--name")
    tool_start.add_argument("tool_argv", nargs=argparse.REMAINDER)

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
        payload[contest_id] = engine.store.read_board_snapshot(contest_id)
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


def _job_status_value(status: Any) -> dict[str, object]:
    return {
        "ref": {
            "job_id": status.ref.job_id,
            "scope_fingerprint": status.ref.scope_fingerprint,
            "runtime_id": status.ref.runtime_id,
            "supervisor_id": status.ref.supervisor_id,
        },
        "status": status.status.value,
        "exit_code": status.exit_code,
        "timed_out": status.timed_out,
        "cancelled": status.cancelled,
        "started_at": status.started_at,
        "finished_at": status.finished_at,
        "reason_code": status.reason_code,
    }


def _job_ref_from_args(
    args: argparse.Namespace,
    engine: ChallengeEngine,
    identity: ChallengeIdentity,
) -> JobRef:
    if not args.job_id or not args.supervisor_id:
        raise CLIError(
            "--job-id와 --supervisor-id를 함께 지정해야 합니다."
        )
    state = engine.store.read_snapshot(identity)
    return JobRef(
        job_id=args.job_id,
        scope_fingerprint=engine.sandbox(state).scope_fingerprint,
        runtime_id=args.runtime_id,
        supervisor_id=args.supervisor_id,
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

        if args.command == "benchmark":
            if args.benchmark_command == "promotion":
                payload = _read_bounded_regular_bytes(
                    args.evidence,
                    maximum=MAX_PROMOTION_EVIDENCE_BYTES,
                    label="promotion evidence",
                )
                evidence = BlindLivePromotionEvidence.from_dict(
                    strict_json_loads(
                        payload,
                        max_bytes=MAX_PROMOTION_EVIDENCE_BYTES,
                    )
                )
                _print_json(evaluate_blind_live_promotion(evidence))
                return 0
            if args.benchmark_command == "freeze":
                _print_json(
                    freeze_promotion_manifest(
                        workspace,
                        args.manifest,
                        args.output,
                    )
                )
                return 0
            if args.benchmark_command == "capture":
                _print_json(
                    capture_promotion_session(
                        workspace,
                        args.manifest,
                        session_id=args.session,
                        output_directory=args.output,
                    )
                )
                return 0
            if args.benchmark_command == "fingerprint":
                _print_json(execution_fingerprint_report(workspace))
                return 0
            if args.benchmark_command == "prepare":
                _print_json(
                    prepare_promotion_session(
                        workspace,
                        args.manifest,
                        session_id=args.session,
                    )
                )
                return 0
            if args.benchmark_command == "finalize":
                _print_json(
                    finalize_promotion_session(
                        workspace,
                        args.manifest,
                        session_id=args.session,
                        human_interventions=args.human_interventions,
                        secret_or_flag_leaks=(
                            args.secret_or_flag_leaks
                        ),
                    )
                )
                return 0
            if args.benchmark_command == "compare":
                _print_json(
                    evaluate_promotion_bundles(
                        workspace,
                        args.manifest,
                        args.bundle,
                    )
                )
                return 0
            if args.benchmark_command == "nyu-stage":
                _print_json(
                    stage_nyu_ctf_bench(
                        workspace,
                        source=args.source,
                        release_commit=args.release_commit,
                        case_ids=tuple(args.cases),
                        output_manifest=args.output_manifest,
                        contest=args.contest,
                        split=args.split,
                        wall_seconds=args.budget_wall_seconds,
                        model_call_limit=args.budget_model_calls,
                        total_token_limit=args.budget_tokens,
                    )
                )
                return 0
            raise AssertionError(
                "처리되지 않은 benchmark 명령: "
                f"{args.benchmark_command}"
            )

        if args.command == "migrate":
            if args.migration_command in {"check", "plan"}:
                report = plan_migration(
                    workspace,
                    migration_id=args.id,
                )
            elif args.migration_command == "apply":
                report = apply_migration(
                    workspace,
                    migration_id=args.id,
                )
            elif args.migration_command == "rollback":
                report = rollback_migration(
                    workspace,
                    migration_id=args.id,
                )
            else:
                raise AssertionError(
                    f"처리되지 않은 migrate 명령: "
                    f"{args.migration_command}"
                )
            _print_json(report)
            return 0

        engine = ChallengeEngine(workspace, config=config)

        if args.command == "init-contest":
            category, challenge = _parse_challenge_spec(args.challenge)
            challenge_format, contest_format = _flag_formats(args)
            state = engine.add_challenge(
                ChallengeIdentity(args.contest, category, challenge),
                challenge_flag_format=challenge_format,
                contest_flag_format=contest_format,
            )
            print(f"문제 폴더 준비 완료: {engine.challenge_input(state.identity)}")
            return 0

        if args.command == "add-challenge":
            if args.unbounded and not (args.reason or "").strip():
                raise CLIError("--unbounded에는 --reason이 필요합니다.")
            if args.reason and not args.unbounded:
                raise CLIError("--reason은 --unbounded와 함께 사용하세요.")
            challenge_format, contest_format = _flag_formats(args)
            state = engine.add_challenge(
                _identity(args),
                description=args.description,
                prompt=_prompt(args) or "",
                targets=args.target,
                budget_seconds=args.budget_seconds,
                unbounded_reason=args.reason if args.unbounded else None,
                challenge_flag_format=challenge_format,
                contest_flag_format=contest_format,
                state_schema_version=STATE_SCHEMA_VERSION,
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
                http_requests_per_second=args.http_rate,
                http_burst=args.http_burst,
            )
            print(
                f"허용 대상 추가: {NetworkTarget.parse(args.target).as_text()} "
                f"(rev={state.revision})"
            )
            return 0

        if args.command == "target":
            identity = _identity(args)
            if args.target_command == "list":
                state = engine.store.read_snapshot(identity)
                _print_json(
                    {
                        "primary_target_id": state.primary_target_id,
                        "configuration_epoch": state.configuration_epoch,
                        "targets": [
                            item.to_dict() for item in state.targets
                        ],
                    }
                )
                return 0
            if args.target_command == "add":
                state = engine.add_network_target(
                    identity,
                    args.endpoint,
                    docker_network=args.docker_network,
                    enforcement=args.enforcement,
                    http_requests_per_second=args.http_rate,
                    http_burst=args.http_burst,
                    purpose=args.purpose,
                    expires_at=args.expires_at,
                )
            elif args.target_command == "select":
                state = engine.select_network_target(
                    identity,
                    args.target_id,
                )
            elif args.target_command == "check":
                state = engine.check_network_target(
                    identity,
                    args.target_id,
                )
            elif args.target_command == "smoke":
                state = engine.smoke_network_target(
                    identity,
                    args.target_id,
                    modes=args.mode,
                    path=args.path,
                    timeout_seconds=args.timeout,
                )
            elif args.target_command == "replace":
                state = engine.replace_network_target(
                    identity,
                    args.target_id,
                    args.endpoint,
                    reason=args.reason,
                    purpose=args.purpose,
                    expires_at=args.expires_at,
                )
            elif args.target_command == "revoke":
                state = engine.revoke_network_target(
                    identity,
                    args.target_id,
                    reason=args.reason,
                )
            else:
                raise AssertionError(
                    f"처리되지 않은 target 명령: {args.target_command}"
                )
            _print_json(
                {
                    "primary_target_id": state.primary_target_id,
                    "configuration_epoch": state.configuration_epoch,
                    "targets": [item.to_dict() for item in state.targets],
                }
            )
            return 0

        if args.command == "knowledge":
            identity = _identity(args)
            store = KnowledgeStore(
                engine.store,
                quota_bytes=(
                    config.runtime.challenge_storage_quota_bytes
                ),
                max_scan_entries=config.runtime.storage_scan_max_entries,
                max_scan_bytes=config.runtime.storage_scan_max_bytes,
            )
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
            thread_continuity = _effective_thread_continuity(args)
            paths = engine.store.challenge_paths(identity)
            state = (
                engine.store.load(identity)
                if paths.state.exists()
                else engine.add_challenge(
                    identity,
                    state_schema_version=STATE_SCHEMA_VERSION,
                )
            )
            try:
                solve_mode_arm(state.metadata, args.mode)
            except ScaffoldBindingError as error:
                raise CLIError(
                    f"평가 scaffold 선택이 고정 manifest와 다릅니다: {error}"
                ) from error
            effective_prompt = prompt if prompt else state.prompt
            if not effective_prompt.strip():
                raise CLIError(
                    "문제풀이 프롬프트가 없습니다. PROMPT 또는 --prompt-file을 "
                    "지정하세요."
                )
            if args.mode == "managed":
                if args.resume_thread is not None:
                    raise CLIError(
                        "--resume-thread is available only in assisted mode"
                    )
                if prompt is not None:
                    engine.update_prompt(identity, prompt)
                managed = ManagedOrchestrator(engine)
                state = managed.run_cycles(
                    identity,
                    max_cycles=args.max_cycles,
                    thread_continuity_policy=thread_continuity,
                )
                print(
                    f"Managed 종료: {identity.key} {state.status.value} "
                    f"rev={state.revision}"
                )
                return 0

            if thread_continuity != "fresh":
                raise CLIError(
                    "--thread-continuity is available only in managed mode"
                )

            if (
                args.mode == "thin"
                and args.resume_thread is not None
                and state.metadata.get("evaluation_prepared") is True
            ):
                raise CLIError(
                    "준비된 thin 평가는 이전 노출이 섞일 수 있는 thread를 "
                    "resume할 수 없습니다."
                )

            def announce_live_session(_prepared: object) -> None:
                if args.mode == "thin":
                    message = (
                        "Thin Live 세션 생성 완료. frontier model 1개, "
                        "logical worker/delegation 0개로 실행합니다."
                    )
                else:
                    message = (
                        "Live 세션 생성 완료. 세 논리 역할은 유지되며 계정 "
                        "한도에 걸린 실제 모델 호출만 대기할 수 있습니다."
                    )
                print(message, flush=True)

            return engine.launch_live(
                identity,
                prompt=prompt if prompt else None,
                resume_thread_id=args.resume_thread,
                scaffold=(
                    THIN_SCAFFOLD
                    if args.mode == "thin"
                    else "ctf_os"
                ),
                on_prepared=announce_live_session,
            )

        if args.command == "preflight":
            report = ManagedOrchestrator(engine).preflight(_identity(args))
            if args.json:
                _print_json(report.to_dict())
            else:
                print(
                    "managed preflight: "
                    + ("ready" if report.ok else "blocked")
                )
                for issue in report.issues:
                    print(f"- {terminal_safe(issue)}")
            return 0 if report.ok else 2

        if args.command == "managed-cycle":
            thread_continuity = _effective_thread_continuity(args)
            note = (
                _read_bounded_text(args.note_file)
                if args.note_file is not None
                else args.note
            )
            state = ManagedOrchestrator(engine).run_cycle(
                _identity(args),
                session_id=args.session_id,
                note=note,
                thread_continuity_policy=thread_continuity,
            )
            if args.json:
                _print_json(state.to_dict())
            else:
                print(
                    f"Managed cycle 완료: {state.identity.key} "
                    f"{state.status.value} rev={state.revision}"
                )
            return 0

        if args.command == "run-challenge":
            identity = _identity(args)
            prompt = _prompt(args)
            thread_continuity = _effective_thread_continuity(args)
            if args.mode == "managed":
                if args.no_tools:
                    raise CLIError(
                        "--no-tools is available only in legacy mode"
                    )
                if prompt is not None:
                    engine.update_prompt(identity, prompt)
                state = ManagedOrchestrator(engine).run_cycles(
                    identity,
                    max_cycles=args.max_cycles,
                    thread_continuity_policy=thread_continuity,
                )
            else:
                if thread_continuity != "fresh":
                    raise CLIError(
                        "--thread-continuity is available only in managed mode"
                    )
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

        if args.command == "session":
            if args.session_command != "cancel":
                raise AssertionError(
                    f"처리되지 않은 session 명령: "
                    f"{args.session_command}"
                )
            state = ManagedOrchestrator(engine).cancel_session(
                _identity(args),
                reason=args.reason,
                target=ChallengeStatus(args.target),
            )
            print(f"session 취소: {state.status.value} rev={state.revision}")
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
            state = engine.store.read_snapshot(_identity(args))
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
            identity = _identity(args)
            state = (
                pause_with_handoff(
                    engine,
                    identity,
                    args.handoff,
                )
                if args.handoff is not None
                else engine.pause(identity)
            )
            print(
                f"PAUSED (resume={state.resume_status.value if state.resume_status else '-'})"
            )
            return 0

        if args.command == "checkpoint":
            _state, checkpoint = create_checkpoint(
                engine,
                _identity(args),
                note=args.note,
            )
            _print_json(checkpoint.to_dict())
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

        if args.command == "pwn-prove-effect":
            state, result = engine.prove_pwn_exploit_effect(
                _identity(args),
                parent_experiment_id=args.parent,
                payload_locator=args.payload,
                timeout_seconds=args.timeout,
            )
            _print_json(
                {
                    "authorities": result.to_dict()["authorities"],
                    "plan_recipe_sha256": (
                        result.plan_recipe_sha256
                    ),
                    "reason_code": result.reason_code,
                    "replay_count": len(result.replays),
                    "state_revision": state.revision,
                    "status": result.status.value,
                    "trusted_expectation_sha256": (
                        result.trusted_expectation_sha256
                    ),
                }
            )
            return 0 if result.status.value == "PROVEN" else 1

        if args.command == "pwn-prove-interaction":
            state, evaluation = engine.prove_pwn_interaction(
                _identity(args),
                parent_experiment_id=args.parent,
                recipe_locator=args.recipe,
                timeout_seconds=args.timeout,
            )
            _print_json(
                {
                    "attack_replay_count": len(
                        evaluation.attack_receipts
                    ),
                    "control_replay_count": len(
                        evaluation.control_receipts
                    ),
                    "evaluation": evaluation.to_dict(),
                    "passed": evaluation.passed,
                    "reason_code": evaluation.reason_code,
                    "state_revision": state.revision,
                    "submission_authorized": False,
                }
            )
            return 0 if evaluation.passed else 1

        if args.command == "web-prove":
            state, result = engine.prove_web_impact(
                _identity(args),
                operator_spec_locator=args.spec,
                driver_locator=args.driver,
                hypothesis_ids=tuple(args.hypothesis),
                timeout_seconds=args.timeout,
            )
            semantic_sha256 = (
                result.semantic_evaluation.sha256
                if result.semantic_evaluation is not None
                else None
            )
            _print_json(
                {
                    "confirmed": result.confirmed,
                    "execution_plan_sha256": (
                        result.execution_plan_sha256
                    ),
                    "reason_codes": list(result.reason_codes),
                    "replay_count": len(result.records),
                    "semantic_evaluation_sha256": semantic_sha256,
                    "state_revision": state.revision,
                    "verdict": result.verdict.value,
                }
            )
            return 0 if result.confirmed else 1

        if args.command == "web-prove-active":
            state, result = engine.prove_web_active_probe(
                _identity(args),
                operator_spec_locator=args.spec,
                driver_locator=args.driver,
                hypothesis_ids=tuple(args.hypothesis),
                timeout_seconds=args.timeout,
            )
            _print_json(
                {
                    "authorities": result["authorities"],
                    "confirmed": result["confirmed"],
                    "evaluation_sha256": result[
                        "evaluation_sha256"
                    ],
                    "mode": result["mode"],
                    "reason_codes": result["reason_codes"],
                    "replay_count": len(
                        result["record_commitments"]
                    ),
                    "state_revision": state.revision,
                }
            )
            return 0 if result["confirmed"] else 1

        if args.command == "web-active-query":
            result = engine.query_web_active_probe(
                _identity(args),
                attempt_id=args.attempt,
            )
            _print_json(result)
            return 0 if result["ok"] else 1

        if args.command == "forensic-prove":
            state, result = engine.prove_forensic_assertion(
                _identity(args),
                operator_spec_locator=args.spec,
                hypothesis_ids=tuple(args.hypothesis),
                timeout_seconds=args.timeout,
            )
            document = result.to_dict()
            _print_json(
                {
                    "authorities": document["authorities"],
                    "confirmed": result.confirmed,
                    "execution_plan_sha256": (
                        result.execution_plan_sha256
                    ),
                    "reason_codes": list(result.reason_codes),
                    "record_count": len(result.records),
                    "semantic_evaluation_sha256": document[
                        "semantic_evaluation_sha256"
                    ],
                    "state_revision": state.revision,
                    "verdict": result.verdict.value,
                }
            )
            return 0 if result.confirmed else 1

        if args.command == "rev-prove-accept":
            state, result = engine.prove_rev_accepted_input(
                _identity(args),
                operator_spec_locator=args.spec,
                timeout_seconds=args.timeout,
            )
            _print_json(
                {
                    "authorities": result["authorities"],
                    "evaluation_sha256": hashlib.sha256(
                        (
                            json.dumps(
                                result,
                                allow_nan=False,
                                ensure_ascii=True,
                                separators=(",", ":"),
                                sort_keys=True,
                            )
                            + "\n"
                        ).encode("ascii")
                    ).hexdigest(),
                    "passed": result["passed"],
                    "reason_codes": result["reason_codes"],
                    "run_count": len(result["observations"]),
                    "state_revision": state.revision,
                }
            )
            return 0 if result["passed"] else 1

        if args.command == "rev-prove-runtime":
            expected_oracle = _read_rev_runtime_expected_oracle(
                args.oracle
            )
            state, result = prove_rev_runtime_accepted_input(
                engine,
                _identity(args),
                runtime_spec_locator=args.runtime_spec,
                accepted_input_path=args.accepted_input_file,
                expected_oracle=expected_oracle,
                timeout_seconds=args.timeout,
            )
            _print_json(
                {
                    "authorities": result["authorities"],
                    "evaluation_sha256": hashlib.sha256(
                        (
                            json.dumps(
                                result,
                                allow_nan=False,
                                ensure_ascii=True,
                                separators=(",", ":"),
                                sort_keys=True,
                            )
                            + "\n"
                        ).encode("ascii")
                    ).hexdigest(),
                    "passed": result["passed"],
                    "reason_codes": result["reason_codes"],
                    "run_count": result["record_count"],
                    "state_revision": state.revision,
                }
            )
            return 0 if result["passed"] else 1

        if args.command == "crypto-prove":
            state, result = engine.prove_crypto_metamorphic_candidate(
                _identity(args),
                args.candidate,
                solver_locator=args.solver,
                original_parameters_locator=args.original_parameters,
                variant_parameters_locator=args.variant_parameters,
                variant_expected_output_locator=(
                    args.variant_expected_output
                ),
                mutation_id=args.mutation_id,
                runtime=args.runtime,
            )
            _print_json(result.to_dict())
            return 0 if result.passed else 1

        if args.command in {
            "managed-oracle-preissue-crypto",
            "oracle-preissue-crypto",
        }:
            state, record = engine.preissue_managed_crypto_oracle(
                _identity(args),
                variant_parameters_path=args.variant_parameters,
                variant_expected_output_path=(
                    args.variant_expected_output
                ),
                mutation_id=args.mutation_id,
            )
            _print_json(
                {
                    **dict(record),
                    "state_revision": state.revision,
                }
            )
            return 0

        if args.command in {
            "managed-oracle-preissue-misc",
            "oracle-preissue-misc",
        }:
            state, record = engine.preissue_managed_misc_oracle(
                _identity(args),
                verifier_path=args.verifier,
                verifier_id=args.verifier_id,
                oracle_id=args.oracle_id,
            )
            _print_json(
                {
                    **dict(record),
                    "state_revision": state.revision,
                }
            )
            return 0

        if args.command in {
            "managed-oracle-preissue-crypto-transcript",
            "oracle-preissue-crypto-transcript",
        }:
            state, record = engine.preissue_managed_crypto_transcript(
                _identity(args),
                peer_path=args.peer,
                peer_data_path=args.peer_data,
            )
            _print_json(
                {
                    **dict(record),
                    "state_revision": state.revision,
                }
            )
            return 0

        if args.command in {
            "managed-oracle-preissue-misc-transcript",
            "oracle-preissue-misc-transcript",
        }:
            state, record = engine.preissue_managed_misc_transcript(
                _identity(args),
                peer_path=args.peer,
                peer_data_path=args.peer_data,
            )
            _print_json(
                {
                    **dict(record),
                    "state_revision": state.revision,
                }
            )
            return 0

        if args.command == "misc-prove":
            state, result = engine.evaluate_misc_transform_candidate(
                _identity(args),
                args.candidate,
                spec_locator=args.spec,
            )
            del state
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
                override_reason=args.override_reason,
            )
            print(
                f"사람 제출 결과 기록 완료: {args.outcome}; "
                f"state={state.status.value}"
            )
            return 0

        if args.command == "export":
            identity = _identity(args)
            destination = export_challenge(
                engine,
                identity,
                include_closure=args.closure,
                redacted=args.redacted,
            )
            print(f"export 완료: {destination}")
            return 0

        if args.command == "close":
            state = close_challenge(
                engine,
                _identity(args),
                portability=args.portability,
            )
            assert state.closure is not None
            _print_json(state.closure.to_dict())
            return 0

        if args.command in {"storage", "gc"}:
            identity = _identity(args)
            storage_command = (
                "gc" if args.command == "gc" else args.storage_command
            )
            if storage_command == "inventory":
                report = storage_inventory(
                    engine.store,
                    identity,
                    quota_bytes=(
                        config.runtime.challenge_storage_quota_bytes
                    ),
                    max_entries=config.runtime.storage_scan_max_entries,
                    max_scan_bytes=config.runtime.storage_scan_max_bytes,
                )
            elif storage_command == "plan":
                report = storage_plan(
                    engine.store,
                    identity,
                    quota_bytes=(
                        config.runtime.challenge_storage_quota_bytes
                    ),
                    max_entries=config.runtime.storage_scan_max_entries,
                    max_scan_bytes=config.runtime.storage_scan_max_bytes,
                )
            elif storage_command == "gc":
                report = quarantine_unreachable(
                    engine.store,
                    identity,
                    max_entries=config.runtime.storage_scan_max_entries,
                    max_scan_bytes=config.runtime.storage_scan_max_bytes,
                )
            elif storage_command == "restore":
                report = restore_quarantine(
                    engine.store,
                    identity,
                    args.quarantine_id,
                )
            elif storage_command == "purge-prepare":
                report = prepare_quarantine_purge(
                    engine.store,
                    identity,
                    args.quarantine_id,
                    max_verify_bytes=config.runtime.storage_scan_max_bytes,
                )
            elif storage_command == "purge":
                report = purge_quarantine(
                    engine.store,
                    identity,
                    args.quarantine_id,
                    manifest_sha256=args.manifest_sha256,
                    confirmation=args.confirm,
                )
            else:
                raise AssertionError(
                    f"처리되지 않은 storage 명령: "
                    f"{storage_command}"
                )
            _print_json(report)
            return 0

        if args.command == "jobs":
            identity = _identity(args)
            _verify_session_scope(identity, engine)
            if args.job_id is None:
                if args.log or args.cancel:
                    raise CLIError(
                        "--log/--cancel에는 --job-id와 "
                        "--supervisor-id가 필요합니다."
                    )
                _state, statuses = engine.list_background_jobs(
                    identity,
                    recover=args.recover,
                )
                _print_json(
                    {
                        "schema_version": 1,
                        "kind": "supervised_job_list",
                        "experiment_id": None,
                        "count": len(statuses),
                        "jobs": [
                            _job_status_value(status)
                            for status in statuses
                        ],
                    }
                )
                return 0
            ref = _job_ref_from_args(args, engine, identity)
            if args.log:
                log = engine.background_job_log(
                    identity,
                    ref,
                    tail_bytes=args.tail_bytes,
                )
                _print_json(
                    {
                        "schema_version": 1,
                        "kind": "supervised_job_log",
                        "ref": _job_status_value(
                            engine.background_job_status(
                                identity,
                                ref,
                            )[1]
                        )["ref"],
                        "stdout": log.stdout,
                        "stderr": log.stderr,
                        "stdout_bytes": log.stdout_bytes,
                        "stderr_bytes": log.stderr_bytes,
                        "stdout_truncated": log.stdout_truncated,
                        "stderr_truncated": log.stderr_truncated,
                    }
                )
                return 0
            if args.cancel:
                _state, status = engine.cancel_background_job(
                    identity,
                    ref,
                    grace_seconds=args.grace,
                )
            else:
                _state, status = engine.background_job_status(
                    identity,
                    ref,
                )
            _print_json(_job_status_value(status))
            return 0

        if args.command == "tool":
            identity = _scoped_identity(args, engine)
            command = _strip_remainder(args.tool_argv)
            if args.tool_command == "start":
                _state, ref = engine.start_background_job(
                    identity,
                    command,
                    name=args.name,
                    timeout_seconds=args.timeout,
                    resource_class=args.profile,
                    network_target=args.target,
                    needs_kvm=args.kvm,
                )
                _print_json(
                    {
                        "schema_version": 1,
                        "kind": "background_job_launch",
                        "ref": {
                            "job_id": ref.job_id,
                            "scope_fingerprint": ref.scope_fingerprint,
                            "runtime_id": ref.runtime_id,
                            "supervisor_id": ref.supervisor_id,
                        },
                    }
                )
                return 0
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
                read_only=args.read_only,
                input_locators=args.input,
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
    except ManagedPreflightBlocked as error:
        print(f"오류: {terminal_safe(error)}", file=sys.stderr)
        return 2
    except ManagedError as error:
        print(f"오류: {terminal_safe(error)}", file=sys.stderr)
        return 1
    except RevRuntimeProofError:
        print(
            "오류: Rev runtime proof를 안전하게 완료하지 못했습니다.",
            file=sys.stderr,
        )
        return 2
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
        MigrationError,
        StorageError,
        ValueError,
        OSError,
    ) as error:
        exit_code = error.exit_code if isinstance(error, CLIError) else 2
        print(f"오류: {terminal_safe(error)}", file=sys.stderr)
        return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
