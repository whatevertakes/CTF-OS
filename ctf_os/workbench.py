"""Human-directed challenge intake and manual Solve Session workbench."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import tempfile
from threading import Event as ThreadEvent, Thread
from typing import Iterable, Mapping, Protocol
from uuid import uuid4

from .artifact_writer import ArtifactWriter
from .config import AppConfig
from .contest_parser import ContestManifest
from .flag_detector import FlagDetector
from .intake import (
    IntakeError,
    IntakeService,
    ZipExtractionLimits,
    _is_template_challenge,
    _validate_archive_metadata,
    materialize_challenge_sources,
)
from .models import Challenge
from .sandbox.container import SandboxScope, SandboxSpec
from .sandbox.docker_cli import DockerCli
from .sandbox.network_policy import parse_remote_endpoints, resolve_remote_endpoints
from .sandbox.pool import DockerSandboxPool
from .solver_engine.codex_cli_backend import CodexCliBackend, CodexExecRequest
from .tactical_engine.planners import default_planner_registry
from .tactical_engine.profiles import ProblemClassifier


MANUAL_SESSION_SCHEMA = 1
SESSION_TERMINAL_STATES = frozenset({"COMPLETED", "STOPPED", "FAILED", "BLOCKED"})
RUNTIME_PROFILES = frozenset({"standard", "nested_podman_trusted_ctf"})
_SUBWORKER_PREFIX = "CTF_OS_SUBWORKER_REQUEST:"
_LEAD_STATE_PREFIX = "CTF_OS_SESSION_STATE:"
_SUBWORKER_ROLES = frozenset({"terra", "luna", "sol"})


class WorkbenchError(ValueError):
    """An operator-actionable manual workbench failure."""


class RuntimePreparationError(WorkbenchError):
    """The selected challenge runtime could not be prepared safely."""


@dataclass(frozen=True, slots=True)
class IntakeReport:
    challenge: Challenge
    status: str
    report_path: Path
    workspace: Path
    blockers: tuple[str, ...] = ()
    detected_files: tuple[str, ...] = ()
    required_tools: tuple[str, ...] = ()
    runtime_requirements: tuple[str, ...] = ()
    tactical_summary: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SubworkerRequest:
    role: str
    scope: str
    task: str


@dataclass(frozen=True, slots=True)
class SolveContext:
    config: AppConfig
    challenge: Challenge
    intake: IntakeReport
    artifact_root: Path
    runtime: str
    lead: str
    max_subworkers: int
    priority: str
    session_id: str


@dataclass(frozen=True, slots=True)
class SolveResult:
    status: str
    lead_output: str = ""
    subworkers: tuple[dict[str, str], ...] = ()
    reason: str = ""


class SolveRunner(Protocol):
    def run(self, context: SolveContext) -> SolveResult: ...


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _append(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(content)


def _promote_regular_tree(source: Path, destination: Path) -> None:
    """Copy only regular, non-symlink worker artifacts below one trusted root."""
    if not source.is_dir() or source.is_symlink():
        return
    for item in sorted(source.rglob("*")):
        if item.is_symlink():
            continue
        relative = item.relative_to(source)
        target = destination / relative
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif item.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(item, target, follow_symlinks=False)


def _promote_lead_artifacts(source: Path, destination: Path) -> None:
    """Promote only the documented lead artifact contract."""
    if not source.is_dir() or source.is_symlink():
        return
    append_names = {"notes.md", "evidence.log", "findings.jsonl"}
    replace_names = {"plan.md", "writeup.md", "handoff.md"}
    for name in sorted(append_names | replace_names):
        item = source / name
        if item.is_file() and not item.is_symlink():
            content = item.read_text(encoding="utf-8", errors="replace")
            if name in append_names:
                _append(destination / name, content)
            else:
                _atomic_write(destination / name, content)
    exploit = source / "exploit"
    _promote_regular_tree(exploit, destination / "exploit")


class ManualIntakeWorkbench:
    """Produce one independent report per human-supplied challenge."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.service = IntakeService(config)

    def run(self, *, materialize: bool = True, write_reports: bool = True) -> tuple[IntakeReport, ...]:
        manifests = self.service.discover_manifests()
        if not manifests:
            raise WorkbenchError(
                f"contest manifest not found: {self.config.incoming_contest_dir() / 'contest.md'}"
            )
        reports: list[IntakeReport] = []
        for manifest in manifests:
            for challenge in manifest.owned_by(self.config.owned_categories):
                # The exception boundary is deliberately per challenge. One
                # hostile/broken ZIP can never suppress a sibling report.
                reports.append(self._inspect_one(
                    manifest, challenge, materialize=materialize, write_report=write_reports,
                ))
        return tuple(reports)

    def _inspect_one(
        self, manifest: ContestManifest, challenge: Challenge, *,
        materialize: bool, write_report: bool,
    ) -> IntakeReport:
        report_path = self.report_path(challenge)
        workspace = self.config.workspace_dir(manifest.name, challenge.slug)
        blockers: list[str] = []
        tools: set[str] = {"file", "python3"}
        runtime: list[str] = ["standard sandbox"]
        files: list[str] = []
        archives: tuple[Path, ...] = ()
        attachments: tuple[Path, ...] = ()
        source_dir: Path | None = None
        docker_files: list[str] = []
        compose_files: list[str] = []

        try:
            if _is_template_challenge(challenge):
                blockers.append("description is still a template value")
            archives = self.service.discover_archives(manifest, challenge)
            attachments = self.service.discover_opaque_attachments(manifest, challenge)
            source_dir = self.service.discover_source_directory(manifest, challenge)
            files.extend(path.name for path in (*archives, *attachments))
            if source_dir is not None:
                source_files = tuple(
                    path for path in source_dir.rglob("*")
                    if path.is_file() and not path.is_symlink()
                )
                files.extend(str(path.relative_to(source_dir)) for path in source_files)
                docker_files.extend(
                    str(path.relative_to(source_dir)) for path in source_files
                    if path.name.casefold() in {"dockerfile", "containerfile"}
                )
                compose_files.extend(
                    str(path.relative_to(source_dir)) for path in source_files
                    if path.name.casefold() in {
                        "compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"
                    }
                )
            endpoints = parse_remote_endpoints(challenge.remote)
            if not archives and not attachments and source_dir is None and not endpoints:
                blockers.append("no matching source, attachment, archive, or authorized remote")
            if archives:
                tools.add("unzip")
                _validate_archive_metadata(
                    archives, ZipExtractionLimits(**self.config.zip_extraction_limits)
                )
            if attachments:
                tools.add("archive-specific sandbox extractor")
                runtime.append("opaque archives must be inspected inside the sandbox")
            if docker_files or compose_files:
                tools.update({"podman", "container build tools"})
                runtime.append(
                    "nested_podman_trusted_ctf may be selected only after human review; "
                    "it expands container privileges and attack surface"
                )
            if not blockers and materialize:
                materialize_challenge_sources(
                    archives, source_dir, workspace, attachments=attachments,
                    zip_limits=ZipExtractionLimits(**self.config.zip_extraction_limits),
                )
        except (IntakeError, OSError, ValueError) as exc:
            blockers.append(str(exc))

        if blockers:
            status = "blocked"
        elif docker_files or compose_files or attachments:
            status = "needs_preparation"
        else:
            status = "ready"
        evidence = [
            challenge.description or "",
            challenge.hint or "",
            challenge.remote or "",
            *files,
        ]
        profile = ProblemClassifier().classify(challenge.category, evidence)
        plan = default_planner_registry().plan(profile)
        tools.update(profile.required_capabilities)
        tactical = (
            f"classified subtype: {profile.category}.{profile.subtype}",
            f"classification confidence: {profile.confidence:.2f}",
            f"planner: {plan.planner_id}",
            "candidate strategies: " + (", ".join(profile.candidate_strategies) or "fast_recon"),
            "contracts: " + (", ".join(contract.id for contract in plan.contracts) or "none"),
            "unresolved questions: " + ("; ".join(profile.unresolved_questions) or "none"),
        )
        report = IntakeReport(
            challenge=challenge,
            status=status,
            report_path=report_path,
            workspace=workspace,
            blockers=tuple(dict.fromkeys(blockers)),
            detected_files=tuple(sorted(dict.fromkeys(files))),
            required_tools=tuple(sorted(tools)),
            runtime_requirements=tuple(dict.fromkeys(runtime)),
            tactical_summary=tactical,
        )
        if write_report:
            _atomic_write(report_path, self._render(report, docker_files, compose_files))
        return report

    def report_path(self, challenge: Challenge) -> Path:
        return self.config.output_contest_dir() / "briefs" / challenge.slug / "intake.md"

    @staticmethod
    def _render(report: IntakeReport, docker_files: Iterable[str], compose_files: Iterable[str]) -> str:
        challenge = report.challenge
        lead = "sol"
        roles = {
            "pwn": "Terra exploit/reproduction; Luna binary and mitigation recon",
            "web": "Luna endpoint/source recon; Terra exploit implementation",
            "rev": "Sol deep analysis; Luna strings/platform recon; Terra tooling scripts",
            "crypto": "Sol mathematical strategy; Terra solver implementation; Luna parameter inventory",
            "forensics": "Luna file/metadata triage; Terra extraction pipeline; Sol evidence review",
        }.get(challenge.category.casefold(), "Luna recon; Terra implementation; Sol strategy/review")
        def lines(values: Iterable[str], empty: str = "none detected") -> str:
            values = tuple(values)
            return "\n".join(f"- {value}" for value in values) if values else f"- {empty}"
        remote = challenge.remote or "none (offline challenge)"
        return f"""# Intake: {challenge.name}

## Challenge

- Name: {challenge.name}
- Category: {challenge.category}
- Score: {challenge.score if challenge.score is not None else 'not provided'}
- Description: {challenge.description or 'not provided'}
- Authorized remote: {remote}
- Admission: **{report.status}**

## Detected input

{lines(report.detected_files)}

### Dockerfile / Containerfile

{lines(docker_files)}

### Compose

{lines(compose_files)}

## Required tools

{lines(report.required_tools)}

## Runtime requirements and risk

{lines(report.runtime_requirements)}

## Blockers

{lines(report.blockers, 'none')}

## Recommended session roles

- Lead model: {lead}
- Scoped workers: {roles}
- Worker ceiling is selected by the human at `ctf-os solve` time.

## Tactical starting point

{lines(report.tactical_summary)}

## Human checks before solving

- Confirm every file came from the authorized CTF challenge.
- Confirm the remote exactly matches the organizer-provided endpoint.
- Review ZIP limits and any archive rejection; do not raise limits blindly.
- Review Dockerfile/Compose before selecting nested Podman.
- Choose lead, maximum subworkers, runtime and priority explicitly.
- Confirm that flag candidates will be reviewed and submitted manually.
"""


class ManualSolveWorkbench:
    """Create and run exactly one operator-selected challenge session."""

    def __init__(self, config: AppConfig, *, runner: SolveRunner | None = None) -> None:
        self.config = config
        self.runner = runner or SecureCodexSolveRunner()

    def start(
        self, selector: str, *, lead: str = "sol", max_subworkers: int = 3,
        runtime: str = "standard", priority: str = "normal",
    ) -> SolveResult:
        if not self.config.model_routing_enabled:
            raise WorkbenchError(
                "model routing is disabled; enable model_routing.enabled before starting solve"
            )
        if not bool(self.config.codex_config.get("enabled", True)):
            raise WorkbenchError("Codex solver is disabled; enable solvers.codex.enabled before starting solve")
        if lead not in _SUBWORKER_ROLES:
            raise WorkbenchError("lead must be one of: sol, terra, luna")
        ceiling = int(self.config.worker_policy.get("manual_max_subworkers_ceiling", 16))
        if not isinstance(max_subworkers, int) or max_subworkers < 0 or max_subworkers > ceiling:
            raise WorkbenchError(f"max-subworkers must be between 0 and {ceiling}")
        if runtime not in RUNTIME_PROFILES:
            raise WorkbenchError(f"unknown runtime profile: {runtime}")
        if priority not in {"low", "normal", "high"}:
            raise WorkbenchError("priority must be one of: low, normal, high")

        intake_reports = ManualIntakeWorkbench(self.config).run()
        intake = self._select(intake_reports, selector)
        if intake.status == "blocked":
            raise WorkbenchError(
                f"challenge intake is blocked: {'; '.join(intake.blockers) or intake.report_path}"
            )
        if runtime == "nested_podman_trusted_ctf":
            profile = self.config.get_mapping("runtime_profiles").get(runtime, {})
            if not isinstance(profile, Mapping) or not profile.get("enabled", False):
                raise WorkbenchError(
                    "nested_podman_trusted_ctf is not enabled; review intake.md and explicitly enable the trusted runtime"
                )
            if shutil.which("podman") is None:
                raise WorkbenchError("nested_podman_trusted_ctf requires podman on this host")
            if not isinstance(profile.get("image"), str) or not str(profile.get("image", "")).strip():
                raise WorkbenchError("nested_podman_trusted_ctf requires an explicitly reviewed runtime image")

        root = self.session_root(intake.challenge)
        existing_session = root / "session.json"
        if existing_session.is_file():
            try:
                existing_status = str(
                    json.loads(existing_session.read_text(encoding="utf-8")).get("status", "")
                ).upper()
            except (OSError, ValueError, TypeError):
                existing_status = ""
            if existing_status in {"RUNNING", "PAUSED"}:
                raise WorkbenchError(
                    f"manual session is already {existing_status.lower()}; stop/resume it explicitly before a new solve"
                )
        self._initialize_artifacts(root, intake.report_path)
        session_id = f"solve_{uuid4().hex}"
        context = SolveContext(
            config=self.config,
            challenge=intake.challenge,
            intake=intake,
            artifact_root=root,
            runtime=runtime,
            lead=lead,
            max_subworkers=max_subworkers,
            priority=priority,
            session_id=session_id,
        )
        _atomic_write(root / "plan.md", f"""# Solve plan

- Challenge: {intake.challenge.category}/{intake.challenge.name}
- Human-selected lead: {lead}
- Human-selected maximum subworkers: {max_subworkers}
- Human-selected runtime: {runtime}
- Human-selected priority: {priority}
- Session ID: {session_id}

The lead will replace this section with its evidence-backed attack strategy.
""")
        self._write_session(context, "RUNNING")
        try:
            result = self.runner.run(context)
        except KeyboardInterrupt:
            result = SolveResult("STOPPED", reason="stopped by operator")
        except RuntimePreparationError as exc:
            self._write_session(context, "BLOCKED", reason=str(exc))
            raise
        except BaseException as exc:
            self._write_session(context, "FAILED", reason=str(exc))
            raise
        if len(result.subworkers) > max_subworkers:
            self._write_session(context, "FAILED", reason="runner exceeded the human-selected subworker ceiling")
            raise WorkbenchError("runner exceeded the human-selected subworker ceiling")
        workers_root = (root / "workers").resolve(strict=False)
        for record in result.subworkers:
            artifact_path = Path(str(record.get("artifact_path", ""))).resolve(strict=False)
            try:
                artifact_path.relative_to(workers_root)
            except ValueError as exc:
                self._write_session(context, "FAILED", reason="subworker artifact path escaped the challenge")
                raise WorkbenchError("subworker artifact path escaped the selected challenge") from exc
        final_status = result.status.upper()
        if final_status not in SESSION_TERMINAL_STATES | {"PAUSED"}:
            final_status = "COMPLETED"
        self._write_session(
            context, final_status, reason=result.reason,
            subworkers=result.subworkers,
        )
        if result.lead_output:
            _append(root / "notes.md", f"\n## Lead result ({_now()})\n\n{result.lead_output}\n")
            self._record_candidates(context, result.lead_output)
        return replace(result, status=final_status)

    def set_state(self, selector: str, state: str) -> Path:
        challenge = self._select_challenge(selector)
        path = self.session_root(challenge) / "session.json"
        if not path.is_file():
            raise WorkbenchError(f"no manual session exists for {challenge.name}")
        data = json.loads(path.read_text(encoding="utf-8"))
        data["status"] = state.upper()
        data["updated_at"] = _now()
        _atomic_write(path, json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        return path

    def session_root(self, challenge: Challenge) -> Path:
        return self.config.output_contest_dir() / challenge.slug

    def _select_challenge(self, selector: str) -> Challenge:
        reports = ManualIntakeWorkbench(self.config).run()
        return self._select(reports, selector).challenge

    @staticmethod
    def _select(reports: Iterable[IntakeReport], selector: str) -> IntakeReport:
        needle = selector.strip().casefold()
        matches = tuple(
            report for report in reports
            if needle in {
                report.challenge.id.casefold(), report.challenge.name.casefold(),
                report.challenge.slug.casefold(), report.challenge.challenge_key.casefold(),
                f"{report.challenge.category}/{report.challenge.name}".casefold(),
            }
        )
        if not matches:
            raise WorkbenchError(f"unknown locally owned challenge: {selector}")
        if len(matches) > 1:
            raise WorkbenchError(f"ambiguous challenge selector: {selector}")
        return matches[0]

    @staticmethod
    def _initialize_artifacts(root: Path, intake_path: Path) -> None:
        root.mkdir(parents=True, exist_ok=True)
        (root / "exploit").mkdir(exist_ok=True)
        (root / "workers").mkdir(exist_ok=True)
        shutil.copyfile(intake_path, root / "intake.md", follow_symlinks=False)
        defaults = {
            "plan.md": "# Solve plan\n\nPending lead strategy.\n",
            "notes.md": "# Notes\n",
            "evidence.log": "",
            "findings.jsonl": "",
            "writeup.md": "# Writeup\n\nNot completed.\n",
            "handoff.md": "# Handoff\n\nNo handoff yet.\n",
        }
        for name, content in defaults.items():
            path = root / name
            if not path.exists():
                _atomic_write(path, content)

    @staticmethod
    def _write_session(
        context: SolveContext, status: str, *, reason: str = "",
        subworkers: Iterable[Mapping[str, str]] = (),
    ) -> None:
        path = context.artifact_root / "session.json"
        created = _now()
        if path.is_file():
            try:
                created = str(json.loads(path.read_text(encoding="utf-8")).get("created_at", created))
            except (OSError, ValueError, TypeError):
                pass
        payload = {
            "schema_version": MANUAL_SESSION_SCHEMA,
            "session_id": context.session_id,
            "challenge_id": context.challenge.id,
            "challenge": context.challenge.name,
            "category": context.challenge.category,
            "lead": context.lead,
            "runtime": context.runtime,
            "max_subworkers": context.max_subworkers,
            "priority": context.priority,
            "status": status,
            "reason": reason,
            "subworkers": list(subworkers),
            "created_at": created,
            "updated_at": _now(),
            "automatic_submission": False,
        }
        _atomic_write(path, json.dumps(payload, indent=2, ensure_ascii=False) + "\n")

    def _record_candidates(self, context: SolveContext, output: str) -> None:
        detector = FlagDetector(self.config.flag_patterns, ignore_placeholders=True)
        for candidate in detector.detect(output):
            finding = {
                "time": _now(), "type": "flag_candidate", "value": candidate,
                "challenge_id": context.challenge.id, "submitted": False,
                "evidence": "lead output; human review and reproduction required",
            }
            _append(context.artifact_root / "findings.jsonl", json.dumps(finding, ensure_ascii=False) + "\n")


class SecureCodexSolveRunner:
    """Run one lead and only its bounded, explicitly requested subworkers."""

    def __init__(self, *, docker: DockerCli | None = None, max_lead_rounds: int = 32) -> None:
        self.docker = docker or DockerCli()
        self.max_lead_rounds = max_lead_rounds

    def run(self, context: SolveContext) -> SolveResult:
        router = context.config.model_router()
        role = "session_leader" if context.lead == "sol" else (
            "implementer" if context.lead == "terra" else "recon"
        )
        selection = router.select(role=role)
        staging_writer = ArtifactWriter(context.config.output_root, context.challenge.contest)
        staging = staging_writer.create_attempt_staging()
        attempt_id = f"lead_{uuid4().hex}"
        pool: DockerSandboxPool | None = None
        resume_id: str | None = None
        worker_records: list[dict[str, str]] = []
        used_scopes: set[str] = set()
        transcript: list[str] = []
        last_lead_state = ""
        cancellation = ThreadEvent()
        watcher_stop = ThreadEvent()
        watcher = Thread(
            target=self._watch_operator_state,
            args=(context, cancellation, watcher_stop),
            name=f"ctf-os-control-{context.session_id}", daemon=True,
        )
        watcher.start()
        try:
            pool = self._sandbox(context, attempt_id, staging.workdir, staging.artifacts)
            backend = CodexCliBackend(
                command=context.config.codex_command, model_router=router,
            )
            prompt = self._lead_prompt(context)
            round_limit = min(self.max_lead_rounds, context.max_subworkers + 2)
            for _ in range(round_limit):
                requested = self._requested_terminal_state(context, cancellation)
                if requested:
                    return SolveResult(requested, "\n".join(transcript), tuple(worker_records), "operator requested stop")
                with (context.artifact_root / "evidence.log").open("a", encoding="utf-8") as evidence:
                    result = backend.run(CodexExecRequest(
                        workdir=staging.workdir,
                        prompt=prompt,
                        role=role,
                        selection=selection,
                        broker_socket=staging.workdir / ".ctf-os-broker",
                        json_events=True,
                        resume_id=resume_id,
                        persistent_session=True,
                    ), timeout_sec=context.config.attempt_timeout_sec("session_leader", 1800),
                        on_output=lambda record: print(f"[lead:{record.stream}] {record.line}", flush=True),
                        evidence_sink=evidence, cancel_event=cancellation)
                transcript.append(result.stdout)
                _promote_lead_artifacts(staging.artifacts, context.artifact_root)
                requested = self._requested_terminal_state(context, cancellation)
                if requested:
                    return SolveResult(requested, "\n".join(transcript), tuple(worker_records), "operator requested stop")
                if result.returncode != 0:
                    return SolveResult("FAILED", "\n".join(transcript), tuple(worker_records), result.stderr or result.status)
                resume_id = result.resume_id or result.session_id or resume_id
                requests = self._parse_requests(result.stdout)
                lead_state, lead_reason = self._parse_lead_state(result.stdout)
                last_lead_state = lead_state
                accepted: list[SubworkerRequest] = []
                for request in requests:
                    if len(worker_records) >= context.max_subworkers:
                        break
                    key = request.scope.strip().casefold()
                    if key and key not in used_scopes:
                        used_scopes.add(key)
                        accepted.append(request)
                if not accepted:
                    if lead_state == "continue":
                        prompt = (
                            "Continue the selected challenge yourself. Record new evidence, change strategy if the "
                            "last approach plateaued, and emit the required session-state line."
                        )
                        continue
                    if lead_state == "blocked":
                        return SolveResult("BLOCKED", "\n".join(transcript), tuple(worker_records), lead_reason)
                    break
                summaries: list[str] = []
                for request in accepted:
                    if cancellation.is_set():
                        break
                    record, summary = self._run_subworker(
                        context, request, len(worker_records) + 1, cancellation,
                    )
                    worker_records.append(record)
                    summaries.append(summary)
                prompt = (
                    "Review these completed scoped worker reports. Update plan/evidence, decide the next "
                    "non-overlapping work, or finish.\n\n" + "\n\n".join(summaries)
                )
            if last_lead_state == "continue":
                return SolveResult(
                    "BLOCKED", "\n".join(transcript), tuple(worker_records),
                    "lead reached the bounded session-turn ceiling without review-ready evidence",
                )
            return SolveResult("COMPLETED", "\n".join(transcript), tuple(worker_records))
        finally:
            watcher_stop.set()
            watcher.join(timeout=1)
            if pool is not None:
                pool.release(attempt_id, remove=True)
            ArtifactWriter.cleanup_attempt_staging(staging.workdir)

    @staticmethod
    def _watch_operator_state(
        context: SolveContext, cancellation: ThreadEvent, stop: ThreadEvent,
    ) -> None:
        path = context.artifact_root / "session.json"
        while not stop.wait(.2):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError, TypeError):
                continue
            if payload.get("session_id") != context.session_id:
                cancellation.set()
                return
            if str(payload.get("status", "")).upper() in {"PAUSED", "STOPPED"}:
                cancellation.set()
                return

    @staticmethod
    def _requested_terminal_state(
        context: SolveContext, cancellation: ThreadEvent,
    ) -> str | None:
        if not cancellation.is_set():
            return None
        try:
            payload = json.loads((context.artifact_root / "session.json").read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return "STOPPED"
        status = str(payload.get("status", "")).upper()
        return status if status in {"PAUSED", "STOPPED"} else "STOPPED"

    def _sandbox(self, context: SolveContext, attempt_id: str, workdir: Path, artifacts: Path) -> DockerSandboxPool:
        scope = SandboxScope(
            context.config.team_id, context.config.member_name, context.challenge.contest,
            context.challenge.name, context.challenge.id, context.challenge.challenge_key,
        )
        pool = DockerSandboxPool(
            scope=scope,
            workspace_root=context.config.incoming_contest_dir(),
            output_root=context.config.output_contest_dir(),
            docker=self.docker,
            max_containers=1,
        )
        memory, cpus = context.config.sandbox_limits
        storage_bytes, storage_inodes = context.config.sandbox_storage_limits
        endpoints = resolve_remote_endpoints(parse_remote_endpoints(context.challenge.remote))
        runtime_config = context.config.get_mapping("runtime_profiles").get(context.runtime, {})
        runtime_image = (
            str(runtime_config.get("image"))
            if context.runtime == "nested_podman_trusted_ctf" and isinstance(runtime_config, Mapping)
            else context.config.sandbox_image
        )
        try:
            pool.precreate(SandboxSpec(
                scope=scope, attempt_id=attempt_id, workspace=context.intake.workspace,
                workdir=workdir, artifacts=artifacts,
                image=runtime_image, memory=memory, cpus=cpus,
                storage_limit_bytes=storage_bytes, storage_inode_limit=storage_inodes,
                endpoints=endpoints,
            ))
        except (OSError, RuntimeError, ValueError) as exc:
            raise RuntimePreparationError(
                f"runtime preparation failed for {context.challenge.name}: {exc}"
            ) from exc
        return pool

    @staticmethod
    def _lead_prompt(context: SolveContext) -> str:
        intake = (context.artifact_root / "intake.md").read_text(encoding="utf-8")
        return f"""You are the {context.lead} lead for exactly one authorized CTF Solve Session.

Challenge: {context.challenge.category}/{context.challenge.name}
Runtime: {context.runtime}
Maximum total subworkers: {context.max_subworkers}
Human priority: {context.priority}

{intake}

Rules:
- Work only on this challenge. Use ./ctf-exec PROGRAM ARG... for every challenge command.
- The container sees challenge input read-only at /workspace and may write only /work and /artifacts.
- Connect only to the authorized remote stated above. Never scan or discover unrelated hosts.
- Never log in to CTFd and never submit a flag.
- Record commands, output, findings, failed hypotheses and reproduction steps in /artifacts.
- A flag-like value is only a candidate until a human reviews and submits it.
- Request a worker only when needed, with a unique non-overlapping scope, using one exact line:
  {_SUBWORKER_PREFIX} {{"role":"terra|luna|sol","scope":"unique scope","task":"bounded task"}}
- Do not request more than the stated ceiling. Review worker results before changing strategy.
- End every lead turn with one exact state line:
  {_LEAD_STATE_PREFIX} {{"status":"continue|ready_for_human_review|blocked","reason":"brief evidence-backed reason"}}
- Use ready_for_human_review only when a reproducible flag candidate or complete decisive evidence is recorded.

Start by writing a concrete attack plan and performing the highest-value safe checks.
"""

    @staticmethod
    def _parse_requests(output: str) -> tuple[SubworkerRequest, ...]:
        requests: list[SubworkerRequest] = []
        for line in output.splitlines():
            if not line.startswith(_SUBWORKER_PREFIX):
                continue
            try:
                value = json.loads(line.removeprefix(_SUBWORKER_PREFIX).strip())
            except json.JSONDecodeError:
                continue
            if not isinstance(value, dict):
                continue
            role = str(value.get("role", "")).casefold()
            scope = str(value.get("scope", "")).strip()[:240]
            task = str(value.get("task", "")).strip()[:2000]
            if role in _SUBWORKER_ROLES and scope and task:
                requests.append(SubworkerRequest(role, scope, task))
        return tuple(requests)

    @staticmethod
    def _parse_lead_state(output: str) -> tuple[str, str]:
        for line in reversed(output.splitlines()):
            if not line.startswith(_LEAD_STATE_PREFIX):
                continue
            try:
                value = json.loads(line.removeprefix(_LEAD_STATE_PREFIX).strip())
            except json.JSONDecodeError:
                return "", "malformed lead state"
            if not isinstance(value, dict):
                return "", "malformed lead state"
            status = str(value.get("status", "")).casefold()
            reason = str(value.get("reason", "")).strip()[:1000]
            if status in {"continue", "ready_for_human_review", "blocked"}:
                return status, reason
            return "", "unknown lead state"
        return "", ""

    def _run_subworker(
        self, context: SolveContext, request: SubworkerRequest, number: int,
        cancellation: ThreadEvent,
    ) -> tuple[dict[str, str], str]:
        worker_id = f"{request.role}-{number:02d}"
        worker_root = context.artifact_root / "workers" / worker_id
        worker_root.mkdir(parents=True, exist_ok=False)
        _atomic_write(worker_root / "scope.md", f"# Scope\n\n{request.scope}\n\n## Task\n\n{request.task}\n")
        writer = ArtifactWriter(context.config.output_root, context.challenge.contest)
        staging = writer.create_attempt_staging()
        attempt_id = f"worker_{uuid4().hex}"
        pool: DockerSandboxPool | None = None
        try:
            pool = self._sandbox(context, attempt_id, staging.workdir, staging.artifacts)
            router = context.config.model_router()
            role = "implementer" if request.role == "terra" else "recon" if request.role == "luna" else "source"
            selection = router.select(role=role)
            backend = CodexCliBackend(command=context.config.codex_command, model_router=router)
            prompt = f"""You are a scoped {request.role} worker for {context.challenge.category}/{context.challenge.name}.
Scope: {request.scope}
Task: {request.task}
Use ./ctf-exec for commands. Work only on this challenge and this scope. Do not modify another
worker's files, access any undeclared remote, log in to CTFd, or submit flags. Record evidence and
reproduction commands. Report flag-like text only as an unsubmitted candidate.
"""
            with (worker_root / "evidence.log").open("a", encoding="utf-8") as evidence:
                result = backend.run(CodexExecRequest(
                    workdir=staging.workdir, prompt=prompt, role=role, selection=selection,
                    broker_socket=staging.workdir / ".ctf-os-broker", json_events=True,
                ), timeout_sec=context.config.attempt_timeout_sec(request.role, 900),
                    on_output=lambda record: print(
                        f"[{worker_id}:{record.stream}] {record.line}", flush=True,
                    ), evidence_sink=evidence, cancel_event=cancellation)
            _promote_regular_tree(staging.artifacts, worker_root / "artifacts")
            _atomic_write(worker_root / "output.md", result.stdout + "\n")
            _atomic_write(worker_root / "stderr.log", result.stderr + "\n")
            record = {
                "worker_id": worker_id, "role": request.role, "scope": request.scope,
                "status": "COMPLETED" if result.returncode == 0 else "FAILED",
                "artifact_path": str(worker_root),
            }
            return record, (
                f"Worker {worker_id} ({request.scope}) status={record['status']}:\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
        finally:
            if pool is not None:
                pool.release(attempt_id, remove=True)
            ArtifactWriter.cleanup_attempt_staging(staging.workdir)


def submission_capability() -> bool:
    """There is intentionally no flag-submission transport in CTF-OS."""
    return False
