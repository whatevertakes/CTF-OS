"""Clean, sandbox-native replay and evidence-bound flag verification."""

from __future__ import annotations

import json
import hashlib
from pathlib import Path
import re
from typing import Mapping, Sequence
import uuid

from .contest import ChallengeSpec, ContestManifest
from .evidence import append_evidence
from .flags import matches_flag, verify_and_record
from .sandbox.network import parse_remotes, resolve_targets
from .sandbox.runtime import SandboxSpec, cleanup, create, execute, stage_artifacts
from .service import ServiceActor, ServiceSpec, service_build, service_cleanup, service_start, service_status
from .workspace import challenge_workspace, resolve_active_run
from .workspace import atomic_json, atomic_text


class ReplayError(RuntimeError):
    pass


PROFILES = {"base", "pwn", "web", "rev", "crypto", "forensic"}
RESOURCE_PROFILES = {"light", "standard", "heavy", "large-forensic"}


def load_contract(solve_root: Path, expected_fingerprint: str) -> dict[str, object]:
    path = solve_root / "REPRODUCE.json"
    if not path.is_file() or path.is_symlink():
        raise ReplayError(f"structured replay contract is missing or unsafe: {path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReplayError(f"cannot read REPRODUCE.json: {exc}") from exc
    if not isinstance(raw, dict) or raw.get("schema_version") != 1:
        raise ReplayError("REPRODUCE.json schema_version must be 1")
    argv = _argv(raw.get("argv"), "argv")
    remote = raw.get("remote_argv")
    if remote is not None:
        _argv(remote, "remote_argv")
    profile = str(raw.get("image_profile", "base"))
    if profile not in PROFILES:
        raise ReplayError(f"image_profile must be one of {', '.join(sorted(PROFILES))}")
    resource = str(raw.get("resource_profile", "standard"))
    if resource not in RESOURCE_PROFILES:
        raise ReplayError(f"resource_profile must be one of {', '.join(sorted(RESOURCE_PROFILES))}")
    if raw.get("input_fingerprint") != expected_fingerprint:
        raise ReplayError("REPRODUCE.json input fingerprint is stale; rebuild the solver contract")
    if raw.get("expected_flag_pattern") is not None and not isinstance(raw["expected_flag_pattern"], str):
        raise ReplayError("expected_flag_pattern must be a string or null")
    for field in ("local_success_pattern", "remote_success_pattern"):
        success_pattern = raw.get(field)
        if success_pattern is None:
            continue
        if not isinstance(success_pattern, str):
            raise ReplayError(f"{field} must be a string or null")
        try:
            re.compile(success_pattern)
        except re.error as exc:
            raise ReplayError(f"invalid {field}: {exc}") from exc
    same_flag_required = raw.get("same_flag_required", False)
    if not isinstance(same_flag_required, bool):
        raise ReplayError("same_flag_required must be a boolean")
    return {**raw, "argv": argv, "same_flag_required": same_flag_required}


def run_replay(
    repo: Path, manifest: ContestManifest, challenge: ChallengeSpec, record: Mapping[str, object],
    *, docker: str = "docker", service_actor: ServiceActor | None = None,
) -> dict[str, object]:
    workspace = Path(str(record["workspace_path"])).resolve()
    fingerprint = str(record["source_fingerprint"])
    solve_root = resolve_active_run(workspace, input_fingerprint=fingerprint)
    contract = load_contract(solve_root, fingerprint)
    exploit = solve_root / "exploit"
    if not exploit.is_dir() or exploit.is_symlink() or not any(path.is_file() and not path.is_symlink() for path in exploit.rglob("*")):
        raise ReplayError("exploit/ must contain a regular solver artifact")
    solver_fingerprint = _solver_fingerprint(exploit)
    pattern = str(contract.get("expected_flag_pattern") or challenge.flag_pattern or "") or None
    if pattern != challenge.flag_pattern:
        raise ReplayError("REPRODUCE.json flag pattern differs from the current manifest")

    service_required = contract.get("service_required") is True
    plan = record.get("service_plan")
    service: ServiceSpec | None = None
    endpoints: tuple[str, ...] = ()
    receipts: list[dict[str, object]] = []
    cleanup_records: list[dict[str, object]] = []
    service_cleanup_record: dict[str, object] | None = None
    actor = service_actor or ServiceActor()
    try:
        if service_required:
            if not isinstance(plan, Mapping) or not plan.get("containerized_challenge") and not record.get("containerized_challenge"):
                # Older intake records put the boolean at record level; plans need only a kind.
                if not plan or not plan.get("kind"):
                    raise ReplayError("service_required is true but intake has no challenge service plan")
            service = ServiceSpec(manifest.slug, challenge.id, workspace / "input", solve_root, plan)
            service_build(service, actor=actor, docker=docker)
            service_start(service, actor=actor, docker=docker)
            current = service_status(service, actor=actor, docker=docker)
            if not current.get("running"):
                raise ReplayError("challenge service did not reach running state")
            endpoints = tuple(
                str(item["internal_target"])
                for item in plan.get("services", [])
                if isinstance(item, Mapping) and item.get("internal_target")
            )
            if not endpoints:
                raise ReplayError("service plan has no internal_target for sandbox replay")

        local_target = endpoints[0] if endpoints else ""
        for ordinal in (1, 2):
            receipt, cleaned = _one_replay(
                solve_root, manifest, challenge, record, contract,
                branch=f"replay-local-{ordinal}", argv=_expand(_argv(contract["argv"], "argv"), local_target),
                service=service, endpoints=endpoints, targets=(), mode="local", docker=docker,
                solver_fingerprint=solver_fingerprint,
            )
            receipts.append(receipt)
            cleanup_records.append(cleaned)

        if service is not None:
            service_cleanup_record = service_cleanup(service, actor=actor, docker=docker)
            service = None

        if challenge.remotes:
            raw_remote = contract.get("remote_argv") or contract["argv"]
            target_text = challenge.remotes[0]
            receipt, cleaned = _one_replay(
                solve_root, manifest, challenge, record, contract,
                branch="replay-remote", argv=_expand(_argv(raw_remote, "remote_argv"), target_text),
                service=None, endpoints=(), targets=resolve_targets(parse_remotes(challenge.remotes)),
                mode="remote", docker=docker,
                solver_fingerprint=solver_fingerprint,
            )
            receipts.append(receipt)
            cleanup_records.append(cleaned)

        local_receipts = receipts[:2]
        local_candidates = [
            _local_candidates(
                str(receipt.get("stdout", "")), pattern,
                str(contract["local_success_pattern"]) if contract.get("local_success_pattern") else None,
            )
            for receipt in local_receipts
        ]
        local_common = set(local_candidates[0]) if local_candidates else set()
        for values in local_candidates[1:]:
            local_common.intersection_update(values)
        local_marker = next(iter(local_common)) if len(local_common) == 1 else None
        local_reproduced = bool(local_marker) and all(receipt.get("exit_code") == 0 for receipt in local_receipts)

        remote_receipt = receipts[2] if challenge.remotes and len(receipts) > 2 else None
        remote_output = str(remote_receipt.get("stdout", "")) if remote_receipt else ""
        remote_candidates = _flag_candidates(remote_output, pattern) if remote_receipt else []
        remote_flag = remote_candidates[0] if len(remote_candidates) == 1 else None
        remote_success_pattern = str(contract.get("remote_success_pattern") or "") or None
        remote_success_marker = bool(
            remote_success_pattern and re.search(remote_success_pattern, remote_output)
        )
        remote_exploit_confirmed = bool(
            remote_receipt
            and remote_receipt.get("exit_code") == 0
            and remote_receipt.get("authorized_network_observed") is True
            and (remote_flag or remote_success_marker)
        )
        exploit_path_matched = _same_exploit_path(contract) and all(
            receipt.get("solver_fingerprint") == solver_fingerprint for receipt in receipts
        )
        flag = remote_flag or local_marker or ""
        refs = {"local": str(receipts[0]["receipt_id"]), "independent": str(receipts[1]["receipt_id"])}
        if challenge.remotes:
            refs["remote"] = str(receipts[2]["receipt_id"])
        verified = verify_and_record(
            solve_root, flag=flag, pattern=pattern, has_remote=bool(challenge.remotes),
            local_reproduced=local_reproduced, independent_rerun=local_reproduced,
            remote_reproduced=remote_exploit_confirmed,
            local_success_marker=local_marker, remote_flag_candidate=remote_flag,
            remote_exploit_confirmed=remote_exploit_confirmed,
            exploit_path_matched=exploit_path_matched,
            same_flag_required=bool(contract["same_flag_required"]),
            local_success_pattern=str(contract["local_success_pattern"]) if contract.get("local_success_pattern") else None,
            remote_success_pattern=remote_success_pattern,
            reproduce_argv=_argv(contract["argv"], "argv"), remote_argv=_argv(contract["remote_argv"], "remote_argv") if contract.get("remote_argv") else None,
            image_profile=str(contract.get("image_profile", "base")),
            resource_profile=str(contract.get("resource_profile", "standard")), service_required=service_required,
            evidence_refs=refs, require_recorded_evidence=True,
            remote_hosts=tuple(target.host for target in parse_remotes(challenge.remotes)), input_fingerprint=fingerprint,
        )
        if solve_root != workspace:
            for name in ("RESULT.md", "reproduce.sh"):
                source = solve_root / name
                if source.is_file() and not source.is_symlink():
                    atomic_text(workspace / name, source.read_text(encoding="utf-8"))
            if (workspace / "reproduce.sh").is_file():
                (workspace / "reproduce.sh").chmod(0o755)
            if (workspace / "STATE.json").is_file():
                compatibility_state = json.loads((solve_root / "STATE.json").read_text(encoding="utf-8"))
                compatibility_state["compatibility_view"] = True
                compatibility_state["authoritative_state"] = str((solve_root / "STATE.json").relative_to(workspace))
                atomic_json(workspace / "STATE.json", compatibility_state)
        return {
            "flag_candidate": flag or None,
            "local_success_marker": local_marker,
            "remote_flag_candidate": remote_flag,
            "receipts": receipts, "cleanup": cleanup_records,
            "service_cleanup": service_cleanup_record, "verification": verified,
            "verdict": verified["verification"]["verdict"],
        }
    finally:
        if service is not None:
            try:
                service_cleanup_record = service_cleanup(service, actor=actor, docker=docker)
            except Exception as exc:
                append_evidence(solve_root / "evidence.log", "replay_cleanup_error", {"scope": "service", "error": str(exc), "input_fingerprint": fingerprint})


def _one_replay(
    solve_root: Path, manifest: ContestManifest, challenge: ChallengeSpec, record: Mapping[str, object],
    contract: Mapping[str, object], *, branch: str, argv: list[str], service: ServiceSpec | None,
    endpoints: tuple[str, ...], targets: Sequence[object], mode: str, docker: str,
    solver_fingerprint: str,
) -> tuple[dict[str, object], dict[str, object]]:
    branch_root = solve_root / "workers" / branch
    sandbox = create(SandboxSpec(
        contest_slug=manifest.slug, challenge_id=challenge.id, branch=branch,
        source=challenge_workspace(solve_root) / "input", branch_root=branch_root,
        input_fingerprint=str(record["source_fingerprint"]), targets=tuple(targets),
        image=f"ctf-os-sandbox:{contract.get('image_profile', 'base')}",
        resource_profile=str(contract.get("resource_profile", "standard")),
        service_network=service.network if service else None, local_endpoints=endpoints,
    ), docker=docker)
    try:
        if _solver_fingerprint(solve_root / "exploit") != solver_fingerprint:
            raise ReplayError("solver artifact changed between clean replay attempts")
        stage_artifacts(sandbox, solve_root / "exploit", "exploit", docker=docker)
        if _solver_fingerprint(solve_root / "exploit") != solver_fingerprint:
            raise ReplayError("solver artifact changed while staging a clean replay")
        result = execute(sandbox, argv, int(contract.get("timeout_seconds", 300)), docker=docker)
        receipt = {
            **result, "event": "replay_exec", "receipt_id": uuid.uuid4().hex,
            "branch": branch, "replay_mode": mode, "clean_sandbox": True,
            "service_running": bool(service), "input_fingerprint": record["source_fingerprint"],
            "solver_fingerprint": solver_fingerprint,
        }
        append_evidence(solve_root / "evidence.log", "replay_exec", {key: value for key, value in receipt.items() if key != "event"})
        return receipt, cleanup(sandbox, docker=docker)
    except Exception:
        try:
            cleanup(sandbox, docker=docker)
        except Exception as cleanup_error:
            append_evidence(solve_root / "evidence.log", "replay_cleanup_error", {"scope": branch, "error": str(cleanup_error), "input_fingerprint": record["source_fingerprint"]})
        raise


def _argv(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not value or not all(isinstance(item, str) and item and "\0" not in item and "\n" not in item and "\r" not in item for item in value):
        raise ReplayError(f"{label} must be a non-empty JSON array of plain argv strings")
    if any(item in {";", "&&", "||", "|", ">", ">>", "<", "2>", "&"} for item in value):
        raise ReplayError(f"{label} cannot contain shell control operators")
    if Path(value[0]).name.casefold() in {"sh", "bash", "dash", "zsh", "fish", "powershell", "pwsh"}:
        raise ReplayError(f"{label} must execute the solver directly, not through a shell")
    return list(value)


def _expand(argv: list[str], target: str) -> list[str]:
    return [item.replace("{target}", target).replace("{local_target}", target).replace("{remote_target}", target) for item in argv]


def _flag_candidates(output: str, pattern: str | None) -> list[str]:
    candidates = re.findall(r"[A-Za-z0-9_]{2,32}\{[^{}\r\n]+\}", output)
    return sorted(set(candidate for candidate in candidates if matches_flag(candidate, pattern)))


def _local_candidates(output: str, flag_pattern: str | None, success_pattern: str | None) -> list[str]:
    if success_pattern:
        return sorted(set(match.group(0) for match in re.finditer(success_pattern, output) if match.group(0)))
    candidates = re.findall(r"[A-Za-z0-9_]{2,32}\{[^{}\r\n]+\}", output)
    if flag_pattern is None:
        return sorted(set(candidates))
    try:
        return sorted(set(candidate for candidate in candidates if re.fullmatch(flag_pattern, candidate)))
    except re.error as exc:
        raise ReplayError(f"invalid local flag pattern: {exc}") from exc


def _same_exploit_path(contract: Mapping[str, object]) -> bool:
    """Compare solver argv while ignoring which target placeholder is used.

    A distinct remote argv is allowed, but it cannot silently prove that the
    locally reproduced exploit path is the path used against the remote.
    """
    local = _canonical_argv(_argv(contract["argv"], "argv"))
    remote_value = contract.get("remote_argv")
    if remote_value is None:
        return True
    return local == _canonical_argv(_argv(remote_value, "remote_argv"))


def _canonical_argv(argv: list[str]) -> list[str]:
    return [
        item.replace("{local_target}", "{target}").replace("{remote_target}", "{target}")
        for item in argv
    ]


def _solver_fingerprint(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_symlink() or (not path.is_dir() and not path.is_file()):
            raise ReplayError(f"solver artifact contains a link or special file: {path}")
        relative = path.relative_to(root).as_posix()
        digest.update(("d" if path.is_dir() else "f").encode())
        digest.update(relative.encode())
        digest.update(b"\0")
        if path.is_file():
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
    return digest.hexdigest()
