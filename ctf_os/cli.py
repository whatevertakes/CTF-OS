"""Command line interface for the local-first CTF-OS node."""

from __future__ import annotations

import argparse
from importlib import resources
import json
from pathlib import Path
import sys
from threading import Event as ThreadEvent
from typing import Callable, Sequence

import yaml

from .application import LocalApplication, PrerequisiteError
from .config import AppConfig, ConfigError, default_config_mapping
from .doctor import run_doctor
from .local_state import CURRENT_SCHEMA_VERSION, LocalState
from .merged_team_state import MergedTeamState
from .model_routing import ModelRouter
from .sandbox.docker_cli import DockerCli
from .sandbox.exec import SandboxExecError, execute_attempt_command
from .solver_engine.codex_cli_backend import CodexCliBackend, CodexExecRequest
from .solver_engine.knowledge import KnowledgeChunk, KnowledgeIndex
from .solver_engine.knowledge_import import audit_snapshot, import_snapshot
from .team_sync import TeamSync
from .tui import CTFOSDashboard, render_tui
from .watcher import PathPollingWatcher


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "model-route":
            return _model_route(args)
        if args.command == "codex-argv":
            return _codex_argv(args)
        if args.command == "init":
            config = _init_workspace(args.contest, Path(args.config), force=args.force)
            print(f"initialized {config.incoming_contest_dir()}")
            return 0
        if args.command == "knowledge":
            return _knowledge_command(args)

        config = AppConfig.from_file(args.config)
        if args.command == "doctor":
            report = run_doctor(config.path, require_non_mock=args.non_mock)
            print(report.render())
            return report.exit_code
        if args.command == "state":
            state_path = config.state_path()
            existed = state_path.is_file()
            LocalState(state_path, team_id=config.team_id)
            action = "migrated" if existed else "initialized"
            print(f"{action} local state: {state_path} (schema v{CURRENT_SCHEMA_VERSION})")
            return 0
        if args.command == "parse":
            challenges = LocalApplication(config).parse()
            print(f"queued {len(challenges)} owned challenge(s)")
            return 0
        if args.command == "retry":
            challenge = LocalApplication(config).retry_challenge(args.challenge)
            print(f"requeued {challenge.name}")
            return 0
        if args.command == "pause":
            result = LocalApplication(config).pause_challenge(args.challenge)
            if result.already_in_target_state:
                print(f"already paused: {result.challenge.name}")
            else:
                details = []
                if result.cancelled_attempt_ids:
                    details.append(f"cancelled={len(result.cancelled_attempt_ids)}")
                if result.released_container_ids:
                    details.append(f"released={len(result.released_container_ids)}")
                print(f"paused {result.challenge.name}" + (f" ({', '.join(details)})" if details else ""))
            return 0
        if args.command == "resume":
            result = LocalApplication(config).resume_challenge(args.challenge)
            print(f"resumed {result.challenge.name}; queued for next local run")
            return 0
        if args.command == "run":
            app = LocalApplication(config)
            memory, cpus = config.sandbox_limits
            print(f"Sandbox image: {config.sandbox_image}")
            print(f"Max concurrent challenges: {config.max_concurrent_challenges}")
            print(f"Max active containers: {config.sandbox_max_containers}")
            print(f"Per-container memory hard limit: {memory.replace('g', ' GiB') if memory.casefold().endswith('g') else memory}")
            print(f"Per-container CPU quota: {float(cpus):g} vCPU")
            print(f"Theoretical maximum quota: {16 * config.sandbox_max_containers} GiB / {2 * config.sandbox_max_containers} vCPU")
            print("Memory reservation: disabled")
            dashboard_config = app.dashboard_config(mock_worker=args.mock_worker)
            def status_update() -> None:
                _print_dashboard(dashboard_config, show_team=True)
            report = app.run(
                once=args.once,
                mock_worker=args.mock_worker,
                auto_confirm_flags=args.auto_confirm_flags or config.auto_confirm_flags,
                # A TTY gets live screen refresh.  Redirected/non-TTY output
                # remains one deterministic final plain renderer instead of a
                # stream of timing-dependent intermediate snapshots.
                on_status=status_update if not args.no_tui and sys.stdout.isatty() else None,
            )
            if report is not None:
                print(f"run complete: parsed={report.parsed_challenges} started={report.started_attempts} solved={report.solved_challenges}" + (" (synthetic mock)" if report.synthetic else ""))
                if not args.no_tui:
                    _print_dashboard(dashboard_config, show_team=True)
            return 0
        if args.command == "tui":
            if args.readonly:
                try:
                    return _watch_readonly_tui(config, show_team=True)
                except KeyboardInterrupt:
                    return 0
            if sys.stdout.isatty() and not args.plain and config.state_path().is_file():
                state = LocalState(config.state_path(), team_id=config.team_id)
                sync = TeamSync(config.sync_root, team_id=config.team_id, member=config.member_name)
                CTFOSDashboard(
                    config, state, team_state=MergedTeamState.from_events(sync.merge_report().events),
                ).run()
                return 0
            _print_dashboard(config, show_team=args.team)
            return 0
        if args.command == "sync":
            sync = TeamSync(config.sync_root, team_id=config.team_id, member=config.member_name)
            if args.sync_command == "merge":
                events = sync.merge()
                for event in events:
                    print(json.dumps(event.to_dict(), ensure_ascii=False, sort_keys=True))
                return 0
            try:
                return _watch_sync(config, sync)
            except KeyboardInterrupt:
                return 0
        if args.command == "sandbox":
            if args.sandbox_command == "exec":
                command = _sandbox_command_argv(args.command_parts)
                result = execute_attempt_command(config, args.attempt_id, command, docker=DockerCli())
                if result.stdout:
                    print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
                if result.stderr:
                    print(result.stderr, end="" if result.stderr.endswith("\n") else "\n", file=sys.stderr)
                return 0 if result.ok else result.returncode or 1
            removed = _cleanup_local_containers(config, all_containers=args.all)
            print(f"removed {len(removed)} sandbox container(s)")
            return 0
    except (ConfigError, PrerequisiteError, SandboxExecError, ValueError, OSError) as exc:
        print(f"ctf-os: {exc}", file=sys.stderr)
        return 2
    parser.error(f"unknown command: {args.command}")
    return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ctf-os")
    subparsers = parser.add_subparsers(dest="command", required=True)

    route_parser = subparsers.add_parser("model-route", help="resolve Codex model routing")
    route_parser.add_argument("--routing-config", default="config/model-routing.yaml")
    route_parser.add_argument("--role")
    route_parser.add_argument("--difficulty")
    route_parser.add_argument("--attempt-kind")
    route_parser.add_argument("--fallback", action="store_true")
    route_parser.add_argument("--json", action="store_true")

    codex_parser = subparsers.add_parser("codex-argv", help="print the codex exec argv for an attempt")
    codex_parser.add_argument("--routing-config", default="config/model-routing.yaml")
    codex_parser.add_argument("--workdir", default=".")
    codex_parser.add_argument("--role")
    codex_parser.add_argument("--difficulty")
    codex_parser.add_argument("--attempt-kind")
    codex_parser.add_argument("--broker-socket", required=True)
    codex_parser.add_argument("prompt")

    knowledge_parser = subparsers.add_parser("knowledge", help="build or query the local CTF knowledge index")
    knowledge_sub = knowledge_parser.add_subparsers(dest="knowledge_command", required=True)
    knowledge_index = knowledge_sub.add_parser("index", help="refresh the local deterministic knowledge index")
    knowledge_index.add_argument("--root", default="knowledge", help="local knowledge root (default: ./knowledge)")
    knowledge_import = knowledge_sub.add_parser("import", help="locally vendor the pinned ctf-skills Markdown snapshot")
    knowledge_import.add_argument("source", help="local ctf-skills checkout; no network fetch is performed")
    knowledge_import.add_argument("--root", default="knowledge", help="local knowledge root (default: ./knowledge)")
    knowledge_import.add_argument("--commit", required=True, help="required pinned source commit")
    knowledge_import.add_argument("--family", action="append", default=[], help="family to include; repeatable (default: approved six)")
    knowledge_import.add_argument("--dry-run", action="store_true", help="validate and report without writing")
    knowledge_import.add_argument("--json", action="store_true", help="emit a structured deterministic report")
    knowledge_audit = knowledge_sub.add_parser("audit", help="verify the local external knowledge snapshot")
    knowledge_audit.add_argument("--root", default="knowledge", help="local knowledge root (default: ./knowledge)")
    knowledge_audit.add_argument("--json", action="store_true", help="emit a structured deterministic report")
    knowledge_query = knowledge_sub.add_parser("query", help="query an already-indexed local knowledge root")
    knowledge_query.add_argument("--root", default="knowledge", help="local knowledge root (default: ./knowledge)")
    knowledge_query.add_argument("--category", help="CTF category filter")
    knowledge_query.add_argument("--text", default="", help="challenge name or free-text query")
    knowledge_query.add_argument("--description", default="", help="challenge description keywords")
    knowledge_query.add_argument("--finding", action="append", default=[], help="observed finding; repeatable")
    knowledge_query.add_argument("--failure", action="append", default=[], help="failed strategy; repeatable")
    knowledge_query.add_argument("--strategy-seed", default="", help="planned strategy keywords")
    knowledge_query.add_argument("--limit", type=int, default=5, help="maximum chunks to return")
    knowledge_query.add_argument("--include-reviewed", action="store_true", help="include reviewed sections in addition to accepted sections")
    knowledge_query.add_argument("--trust", action="append", default=None, help="explicit trust filter; repeatable")
    knowledge_query.add_argument("--json", action="store_true", help="emit structured local results")

    init_parser = subparsers.add_parser("init", help="create a local contest workspace")
    init_parser.add_argument("contest")
    init_parser.add_argument("--force", action="store_true")
    init_parser.add_argument("--config", default="config.yaml")

    for name, help_text in (("doctor", "check local prerequisites"), ("parse", "parse owned local challenges")):
        command = subparsers.add_parser(name, help=help_text)
        command.add_argument("--config", default="config.yaml")
        if name == "doctor":
            command.add_argument("--non-mock", action="store_true", help="fail unless Codex, Docker, image, and broker prerequisites are ready")

    state_parser = subparsers.add_parser("state", help="manage this node's local SQLite state")
    state_sub = state_parser.add_subparsers(dest="state_command", required=True)
    migrate_parser = state_sub.add_parser("migrate", help="apply idempotent local SQLite schema migrations")
    migrate_parser.add_argument("--config", default="config.yaml")

    run_parser = subparsers.add_parser("run", help="run this local node")
    run_parser.add_argument("--config", default="config.yaml")
    run_parser.add_argument("--once", action="store_true")
    run_parser.add_argument("--mock-worker", action="store_true")
    run_parser.add_argument("--auto-confirm-flags", action="store_true")
    run_parser.add_argument("--no-tui", action="store_true")

    retry_parser = subparsers.add_parser("retry", help="explicitly requeue one failed local challenge")
    retry_parser.add_argument("challenge", help="local challenge name, slug, or id")
    retry_parser.add_argument("--config", default="config.yaml")

    pause_parser = subparsers.add_parser("pause", help="pause one locally owned challenge")
    pause_parser.add_argument("challenge", help="local challenge name, slug, or id")
    pause_parser.add_argument("--config", default="config.yaml")

    resume_parser = subparsers.add_parser("resume", help="requeue one paused local challenge")
    resume_parser.add_argument("challenge", help="local challenge name, slug, or id")
    resume_parser.add_argument("--config", default="config.yaml")

    tui_parser = subparsers.add_parser("tui", help="render a deterministic local dashboard")
    tui_parser.add_argument("--config", default="config.yaml")
    tui_parser.add_argument("--team", action="store_true")
    tui_parser.add_argument("--readonly", action="store_true", help="poll the local dashboard read-only until Ctrl-C")
    tui_parser.add_argument("--plain", action="store_true", help="use the deterministic plain/Rich-compatible fallback")

    sync_parser = subparsers.add_parser("sync", help="read the append-only team ledger")
    sync_parser.add_argument("sync_command", choices=("merge", "watch"))
    sync_parser.add_argument("--config", default="config.yaml")

    sandbox_parser = subparsers.add_parser("sandbox", help="Docker-only sandbox commands")
    sandbox_sub = sandbox_parser.add_subparsers(dest="sandbox_command", required=True)
    exec_parser = sandbox_sub.add_parser("exec", help="execute one command inside a local attempt container")
    exec_parser.add_argument("--config", default="config.yaml")
    exec_parser.add_argument("attempt_id")
    exec_parser.add_argument("command_parts", nargs="+", help="pass PROGRAM and arguments after --")
    cleanup_parser = sandbox_sub.add_parser("cleanup", help="remove this node's labeled sandbox containers")
    cleanup_parser.add_argument("--all", action="store_true", help="include all contests for this team/member, still label-filtered")
    cleanup_parser.add_argument("--config", default="config.yaml")
    return parser


def _model_route(args: argparse.Namespace) -> int:
    router = ModelRouter.from_file(args.routing_config)
    selection = router.select(role=args.role, difficulty=args.difficulty, attempt_kind=args.attempt_kind)
    if args.fallback:
        selection = router.select_fallback(selection)
    payload = {"role": selection.role, "profile": selection.profile, "model": selection.model,
               "reasoning_effort": selection.reasoning_effort, "fallback_model": selection.fallback_model}
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    else:
        print(f"{payload['profile']}: {payload['model']} reasoning={payload['reasoning_effort']}")
    return 0


def _codex_argv(args: argparse.Namespace) -> int:
    backend = CodexCliBackend(model_router=ModelRouter.from_file(args.routing_config))
    request = CodexExecRequest(workdir=Path(args.workdir), prompt=args.prompt, role=args.role,
                               difficulty=args.difficulty, attempt_kind=args.attempt_kind,
                               broker_socket=Path(args.broker_socket))
    print(json.dumps(backend.build_exec_argv(request), ensure_ascii=False))
    return 0


def _knowledge_root(value: str) -> Path:
    """Materialize packaged seed content only for a missing default local root."""
    root = Path(value).expanduser()
    if root.exists():
        return root
    return KnowledgeIndex.initialize_default_root(root)


def _knowledge_command(args: argparse.Namespace) -> int:
    if args.knowledge_command == "import":
        root = Path(args.root).expanduser() if args.dry_run else _knowledge_root(args.root)
        result = import_snapshot(
            args.source, root / "external" / "ctf-skills", commit=args.commit,
            families=tuple(args.family) or None, dry_run=args.dry_run,
        )
        if args.json:
            print(json.dumps(result.to_dict(), ensure_ascii=False, sort_keys=True))
        else:
            action = "validated" if result.dry_run else "imported"
            print(f"{action} {result.file_count} file(s), {result.total_bytes} byte(s) in {result.destination}")
        return 0
    if args.knowledge_command == "audit":
        root = Path(args.root).expanduser()
        report = audit_snapshot(root / "external" / "ctf-skills")
        if args.json:
            print(json.dumps(report.to_dict(), ensure_ascii=False, sort_keys=True))
        else:
            state = "valid" if report.valid else "invalid"
            print(f"external knowledge snapshot: {state}; files={report.file_count} bytes={report.total_bytes}")
            for error in report.errors:
                print(f"audit: {error}", file=sys.stderr)
        return 0 if report.valid else 2

    root = _knowledge_root(args.root)
    if args.knowledge_command == "index":
        result = KnowledgeIndex.refresh(root)
        print(f"indexed {result.chunk_count} chunk(s) in {result.database}")
        if result.skipped_files:
            print(f"skipped {len(result.skipped_files)} unsafe or unsupported file(s)", file=sys.stderr)
        return 0
    index = KnowledgeIndex.open_root(root)
    try:
        chunks = index.retrieve(
            args.text,
            category=args.category,
            trust=tuple(args.trust) if args.trust else None,
            include_reviewed=args.include_reviewed,
            limit=args.limit,
            challenge_name=args.text,
            description=args.description,
            failures=tuple(args.failure),
            findings=tuple(args.finding),
            strategy_seed=args.strategy_seed,
        )
    finally:
        index.close()
    if args.json:
        print(json.dumps([_knowledge_chunk_payload(chunk) for chunk in chunks], ensure_ascii=False, sort_keys=True))
    else:
        for chunk in chunks:
            print(_render_knowledge_chunk(chunk))
    return 0


def _knowledge_chunk_payload(chunk: KnowledgeChunk) -> dict[str, object]:
    return {
        "id": chunk.id,
        "source": chunk.source,
        "category": chunk.category,
        "tags": list(chunk.tags),
        "tools": list(chunk.tools),
        "trust": chunk.trust,
        "provenance": dict(chunk.provenance),
        "flags": list(chunk.flags),
        "truncated": chunk.truncated,
        "links": list(chunk.links),
        "content": chunk.content,
    }


def _render_knowledge_chunk(chunk: KnowledgeChunk) -> str:
    """A bounded, provenance-bearing block ready to place in a solver prompt."""
    tags = ", ".join(chunk.tags) or "-"
    tools = ", ".join(chunk.tools) or "-"
    return (
        f"[knowledge id={chunk.id} source={chunk.source} category={chunk.category} trust={chunk.trust}]\n"
        f"tags: {tags}\ntools: {tools}\nflags: {', '.join(chunk.flags) or '-'}\n{chunk.content}\n"
    )


def _dashboard_text(config: AppConfig, *, show_team: bool) -> str:
    """Read status without claiming work or creating an empty state database."""
    state = (
        LocalState(config.state_path(), team_id=config.team_id)
        if config.state_path().is_file()
        else None
    )
    sync = TeamSync(config.sync_root, team_id=config.team_id, member=config.member_name)
    report = sync.merge_report()
    return render_tui(
        config,
        state,
        team_state=MergedTeamState.from_events(report.events),
        show_team=show_team,
        sync_diagnostics=report.diagnostics,
    )


def _print_dashboard(config: AppConfig, *, show_team: bool, printer: Callable[[str], None] = print) -> str:
    dashboard = _dashboard_text(config, show_team=show_team)
    if printer is print and sys.stdout.isatty():
        print("\x1b[2J\x1b[H" + dashboard, flush=True)
    else:
        printer(dashboard)
    return dashboard


def _watch_readonly_tui(
    config: AppConfig,
    *,
    show_team: bool,
    stop_event: ThreadEvent | None = None,
    printer: Callable[[str], None] = print,
) -> int:
    """Poll only local SQLite/TeamSync files; never run or control workers."""
    watcher = PathPollingWatcher(
        (config.state_path(), config.sync_root / config.team_id),
        interval_sec=config.poll_interval_sec,
        include=lambda path: path.name.startswith("local_state.db") or path.name.endswith(".events.jsonl"),
    )
    while True:
        if watcher.changed():
            _print_dashboard(config, show_team=show_team, printer=printer)
        if stop_event is not None and stop_event.is_set():
            return 0
        if not watcher.wait(stop_event):
            return 0


def _sync_watch_signature(sync) -> tuple[object, ...]:
    merged = MergedTeamState.from_events(sync.events)
    challenges = tuple(
        (item.key, item.status, item.solved_flag, item.candidate_flag, item.running_members, item.duplicate_running)
        for item in sorted(merged.challenges.values(), key=lambda value: value.key)
    )
    diagnostics = tuple((item.path, item.line, item.kind, item.message) for item in sync.diagnostics)
    return challenges, diagnostics


def _render_sync_watch_update(sync) -> str:
    """Render changed TeamSync reduction plus non-mutating tail diagnostics."""
    merged = MergedTeamState.from_events(sync.events)
    lines: list[str] = []
    for item in sorted(merged.challenges.values(), key=lambda value: value.key):
        details = [f"status={item.status}", f"running={','.join(item.running_members) or '-'}"]
        if item.candidate_flag:
            details.append(f"candidate={item.candidate_flag}")
        if item.solved_flag:
            details.append(f"solved={item.solved_flag}")
        if item.duplicate_running:
            details.append("duplicate=true")
        lines.append(f"MERGED {item.key}: {' '.join(details)}")
    if not lines:
        lines.append("MERGED state: empty")
    for diagnostic in sync.diagnostics:
        lines.append(f"DIAGNOSTIC {diagnostic.kind}: {diagnostic.message}")
    return "\n".join(lines)


def _watch_sync(config: AppConfig, sync: TeamSync, *, stop_event: ThreadEvent | None = None) -> int:
    """Watch append-only TeamSync files without dispatching any remote work."""
    watcher = PathPollingWatcher(
        (sync.team_directory,),
        interval_sec=config.poll_interval_sec,
        include=lambda path: path.name.endswith(".events.jsonl"),
    )
    previous: tuple[object, ...] | None = None
    while True:
        if watcher.changed():
            report = sync.merge_report()
            current = _sync_watch_signature(report)
            if current != previous:
                print(_render_sync_watch_update(report), flush=True)
                previous = current
        if stop_event is not None and stop_event.is_set():
            return 0
        if not watcher.wait(stop_event):
            return 0


def _init_workspace(contest: str, config_path: Path, *, force: bool) -> AppConfig:
    config_path = config_path.expanduser().resolve(strict=False)
    if config_path.exists():
        config = AppConfig.from_file(config_path)
        if config.contest_name != contest:
            raise ValueError(
                f"config contest.name {config.contest_name!r} does not match requested init contest {contest!r}; "
                "refusing to create an inconsistent workspace"
            )
    else:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(yaml.safe_dump(default_config_mapping(contest), allow_unicode=True, sort_keys=False), encoding="utf-8")
        config = AppConfig.from_file(config_path)
    contest_root = config.incoming_contest_dir()
    manifest = contest_root / "contest.md"
    if manifest.exists() and not force:
        raise FileExistsError(f"refusing to overwrite existing manifest without --force: {manifest}")
    contest_root.mkdir(parents=True, exist_ok=True)
    config.output_contest_dir().mkdir(parents=True, exist_ok=True)
    (config.sync_root / config.team_id).mkdir(parents=True, exist_ok=True)
    routing_path = config.model_routing_path
    if not routing_path.exists():
        routing_path.parent.mkdir(parents=True, exist_ok=True)
        routing_path.write_text(
            resources.files("ctf_os.resources").joinpath("model-routing.yaml").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
    manifest.write_text(
        f"# 대회명: {contest}\n\n## 대회 정보\n- 팀: {config.team_id}\n\n## 문제 목록\n\n"
        "<!-- Add one ### category/challenge section before parsing. -->\n",
        encoding="utf-8",
    )
    return config


def _sandbox_command_argv(parts: Sequence[str]) -> list[str]:
    values = list(parts)
    if values and values[0] == "--":
        values.pop(0)
    if not values or any(not value or any(ord(character) < 32 or ord(character) == 127 for character in value) for value in values):
        raise ValueError("sandbox exec requires PROGRAM [ARG ...] after --")
    if values[0].startswith("-"):
        raise ValueError("sandbox exec program must not start with '-'")
    return values


def _cleanup_local_containers(config: AppConfig, *, all_containers: bool, docker: DockerCli | None = None) -> list[str]:
    """Remove only current-member label matches; never target unlabeled Docker state."""
    adapter = docker or DockerCli()
    filters = ["label=ctf-os=true", f"label=ctf-os.team_id={config.team_id}", f"label=ctf-os.member={config.member_name}"]
    if not all_containers:
        filters.append(f"label=ctf-os.contest={config.contest_name}")
    removed: list[str] = []
    for container_id in adapter.list_container_ids(filters):
        if adapter.remove(container_id).ok:
            removed.append(container_id)
    return removed


if __name__ == "__main__":
    raise SystemExit(main())
