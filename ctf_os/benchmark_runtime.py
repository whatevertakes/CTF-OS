"""Benchmark launcher contract that prepares attempts but never launches models."""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .attempts import challenge_instance_id, challenge_snapshot_digest
from .benchmark_lock import verify_benchmark_lock
from .benchmark_manifest import create_benchmark_manifest, validate_manifest
from .benchmark_schedule import MODES, validate_schedule
from .delegation import load_templates
from .modes import SolveMode
from .race import _template_spec
from .race_lineage import lineage_state, plan_race_generation
from .workspace import atomic_json, resolve_exact_run, start_fresh_attempt


BENCHMARK_CONTEXT_SCHEMA_VERSION = 1


class BenchmarkRuntimeError(ValueError):
    pass


def start_benchmark_attempt(
    repo: Path,
    workspace: Path,
    challenge: object,
    *,
    input_fingerprint: str,
    target_revision: int,
    schedule: Mapping[str, Any],
    schedule_entry_id: str,
    lock_path: Path,
    signature_path: Path,
    public_keys: Mapping[str, Ed25519PublicKey | bytes | Path],
    target_image_digest: str,
    tool_image_digest: str,
    challenge_archive_path: Path,
    template_path: Path | None = None,
) -> dict[str, Any]:
    """Create one exact fresh attempt; no ACTIVE_RUN resolution or model lifecycle."""

    validate_schedule(schedule)
    entry = next((row for row in schedule["entries"] if row["schedule_entry_id"] == schedule_entry_id), None)
    if entry is None:
        raise BenchmarkRuntimeError("schedule entry is not preregistered")
    commit, clean, dirty_digest = _git_identity(repo)
    snapshot = challenge_snapshot_digest(
        workspace, challenge, input_fingerprint=input_fingerprint,
        target_revision=target_revision,
        transformation_seed=entry["transformation_seed"],
        local_target_image_digest=target_image_digest,
    )
    if snapshot != entry["challenge_snapshot_digest"]:
        raise BenchmarkRuntimeError("prepared challenge snapshot does not match schedule")
    instance = challenge_instance_id(
        challenge_id=str(getattr(challenge, "id")), input_fingerprint=input_fingerprint,
        target_revision=target_revision, challenge_snapshot_digest=snapshot,
        transformation_seed=entry["transformation_seed"],
    )
    if instance != entry["challenge_instance_id"]:
        raise BenchmarkRuntimeError("challenge_instance_id does not match schedule")
    verified = verify_benchmark_lock(
        lock_path, signature_path, public_keys,
        expected_commit=commit, worktree_clean=clean,
        expected_challenge_snapshot_digest=snapshot,
        expected_target_image_digest=target_image_digest,
        expected_tool_image_digest=tool_image_digest,
    )
    lock = verified["payload"]
    if schedule["schedule_digest"] != lock["schedule_digest"]:
        raise BenchmarkRuntimeError("schedule digest does not match signed benchmark lock")
    if str(schedule["randomization_seed"]) != str(lock["randomization_seed"]):
        raise BenchmarkRuntimeError("schedule randomization seed differs from signed lock")
    archive_digest = _file_sha256(challenge_archive_path, "challenge archive")
    if archive_digest != lock["challenge_archive_sha256"]:
        raise BenchmarkRuntimeError("challenge archive digest does not match signed lock")
    cli_hash = _cli_build_hash(repo)
    if cli_hash != lock["cli_build_hash"]:
        raise BenchmarkRuntimeError("CLI build hash does not match signed lock")
    docker = _docker_identity(required=True)
    host_observation = _validate_host_requirements(repo, lock["host_requirements"], docker)
    _verify_local_image_digest(target_image_digest)
    _verify_local_image_digest(tool_image_digest)
    if lock["configuration_digest"] != schedule.get("configuration_digest", lock["configuration_digest"]):
        raise BenchmarkRuntimeError("schedule and lock arm configuration digests differ")
    if lock["network_profile"] != entry["network_profile"]:
        raise BenchmarkRuntimeError("schedule and lock network profiles differ")
    if lock["canonical_arm_configuration"].get(entry["arm"], {}).get("mode") != entry["mode"]:
        raise BenchmarkRuntimeError("schedule arm treatment differs from signed lock")
    expected_model_policy = {
        "requested_model": lock["requested_model"],
        "runtime_model_observation_policy": lock["runtime_model_observation_policy"],
        "surface": lock["surface"], "reasoning": lock["reasoning"],
    }
    if entry["model_policy"] != expected_model_policy:
        raise BenchmarkRuntimeError("schedule model policy differs from signed lock")
    if entry["host_envelope"] != lock["host_requirements"]:
        raise BenchmarkRuntimeError("schedule host envelope differs from signed lock")
    if entry["target_snapshot_digest"] not in {
        target_image_digest, target_image_digest.removeprefix("sha256:"),
    }:
        raise BenchmarkRuntimeError("schedule target snapshot differs from resolved target image")
    state_mode = SolveMode.SOL_ONLY if entry["arm"] in {"A", "B"} else SolveMode(entry["mode"])
    run = start_fresh_attempt(
        workspace, challenge, input_fingerprint, target_revision=target_revision,
        attempt_id=str(entry["attempt_id"]), transformation_seed=entry["transformation_seed"],
        mode=state_mode, requested_model=str(lock["requested_model"]),
        requested_reasoning=str(lock["reasoning"]), publish_active=False,
        local_target_image_digest=target_image_digest,
    )
    state = json.loads((run / "STATE.json").read_text(encoding="utf-8"))
    if state["challenge_instance_id"] != instance or state["attempt_id"] != entry["attempt_id"]:
        raise BenchmarkRuntimeError("fresh attempt identity does not match schedule")
    context = _context(
        entry, run, challenge, template_path=template_path,
    )
    atomic_json(run / "BENCHMARK_CONTEXT.json", context)
    source_environment = {
        "git_commit": commit, "dirty_diff_digest": dirty_digest,
        "target_image_digest": target_image_digest, "tool_image_digest": tool_image_digest,
        "cli_build_hash": cli_hash,
        "observed_model": None, "observed_reasoning": None,
        "runtime_observation_evidence": None,
        "host": {
            "system": platform.system(), "kernel": platform.release(),
            "machine": platform.machine(), **host_observation,
            "gpu_policy": lock["host_requirements"]["gpu"],
        },
        "docker": docker,
    }
    manifest = create_benchmark_manifest(
        run, schedule_entry={**entry, "run_id": run.name},
        lock_payload=lock, lock_digest=verified["lock_digest"],
        source_environment=source_environment,
    )
    if entry["arm"] == "C":
        branch_rows = context["frozen_branch_intents"]
        plan_race_generation(
            run, race_id=f"benchmark-{entry['schedule_entry_id']}",
            mode=SolveMode.FIXED_RACE, parent_session_id="sol-main",
            branches=branch_rows, frozen_template=True,
        )
    return {
        "run_id": run.name, "attempt_id": state["attempt_id"],
        "challenge_instance_id": state["challenge_instance_id"],
        "run_path": str(run), "active_run_pointer_used": False,
        "arm": entry["arm"], "mode": entry["mode"],
        "context_path": str(run / "BENCHMARK_CONTEXT.json"),
        "manifest_path": str(run / "RUN_MANIFEST.json"),
        "receipt_endpoint": {"run_id": run.name, "path": str(run), "exact_run_required": True},
        "target_health": {
            "cadence_seconds": 60, "required": ["RUN_START", "EVERY_60_SECONDS", "RUN_END"],
            "model_launcher": False,
        },
        "model_session_launched": False,
    }


def validate_benchmark_completion(run: Path) -> dict[str, Any]:
    manifest = json.loads((run / "RUN_MANIFEST.json").read_text(encoding="utf-8"))
    arm = manifest.get("arm")
    lineage = lineage_state(run)
    if arm == "A":
        if lineage["branches"] or (run / "control-actions.jsonl").read_text(encoding="utf-8").strip():
            raise BenchmarkRuntimeError("Arm A used forbidden orchestration state")
    if arm == "B" and lineage["branches"]:
        raise BenchmarkRuntimeError("Arm B must have zero child branches")
    if arm == "C":
        branches = lineage["current_branches"]
        ran = [row for row in branches if any(
            event["event"] == "RUNNING" for event in row["lifecycle_history"]
        )]
        if len(branches) != 3 or len(ran) != 3:
            manifest["outcome"].update({
                "environment_failure": True,
                "invalidation_reason": "INVALID_MATCHED_BLOCK_FIXED_RACE_LIFECYCLE",
            })
            atomic_json(run / "RUN_MANIFEST.json", manifest)
            raise BenchmarkRuntimeError(
                "fixed-race treatment is invalid unless all three child lanes reach RUNNING"
            )
        if any(row.get("supersedes_branch_id") for row in branches):
            raise BenchmarkRuntimeError("fixed-race forbids replacement")
    if arm == "D":
        if any(value > 3 for value in _active_width_timeline(lineage["branches"])):
            raise BenchmarkRuntimeError("adaptive-race exceeded three active child lanes")
        replacements = [row for row in lineage["branches"] if row.get("supersedes_branch_id")]
        if len(replacements) > 1:
            raise BenchmarkRuntimeError("adaptive-race exceeded one replacement")
    manifest.setdefault("runtime", {})["branch_routing_observations"] = [
        _branch_routing_observation(branch) for branch in lineage["branches"]
    ]
    manifest["runtime"]["model_routing_diagnostic_layer"] = (
        "SEPARATE_FROM_ABCD_TREATMENT"
    )
    atomic_json(run / "RUN_MANIFEST.json", manifest)
    validate_manifest(manifest, require_complete=True)
    return {"valid": True, "run_id": run.name, "arm": arm}


def _context(
    entry: Mapping[str, Any], run: Path, challenge: object,
    *, template_path: Path | None,
) -> dict[str, Any]:
    arm = str(entry["arm"])
    base: dict[str, Any] = {
        "schema_version": BENCHMARK_CONTEXT_SCHEMA_VERSION,
        "arm": arm, "mode": entry["mode"], "run_id": run.name,
        "attempt_id": entry["attempt_id"], "exact_run_required": True,
        "objective": "FIRST_VALID_FLAG", "model_session_launched_by_python": False,
        "receipt_endpoint": str(run),
    }
    if arm == "A":
        base.update({
            "wrapper": "PLAIN_SOL", "race_plan": None, "scheduler_prompt": None,
            "event_management_prompt": None, "child_lanes": [], "replacement": None,
            "control_action_intervention": None,
        })
    elif arm == "B":
        base.update({"wrapper": "CTF_OS", "child_lanes": [], "active_child_width": 0})
    elif arm == "C":
        path = template_path or Path(__file__).parent / "resources" / "delegation-templates.yaml"
        templates = load_templates(path)
        category = str(getattr(challenge, "category", "misc"))
        selected = category if category in templates else "misc"
        rows = templates[selected]["tier_2"][:3]
        specs = [_template_spec(row, index=index, category=selected) for index, row in enumerate(rows)]
        base["frozen_branch_intents"] = [
            {
                "branch_id": spec.session_id, "session_id": spec.session_id,
                "hypothesis_family": spec.hypothesis_family, "role": spec.role,
                "hypothesis": spec.hypothesis, "scope": list(spec.scope),
                "tool_strategy": list(spec.tool_strategy),
                "expected_artifacts": list(spec.expected_artifacts),
                "requested_model_role": spec.requested_model_role,
                # Preserve the preregistered A/B/C/D fixed-race treatment.
                # Branch-model routing is a separate diagnostic layer.
                "requested_reasoning": "high",
            }
            for spec in specs
        ]
        base.update({
            "replacement_limit": 0, "evidence_driven_width_changes": False,
            "maximum_model_concurrency": 4,
        })
    else:
        base.update({
            "initial_active_child_width": 0, "bounded_observation_seconds": [60, 90],
            "child_width_range": [0, 3], "distinct_mechanisms_required": True,
            "replacement_limit": 1, "replacement_requires": ["PLATEAU", "REFUTATION"],
            "maximum_model_concurrency": 4,
        })
    return base


def _git_identity(repo: Path) -> tuple[str, bool, str]:
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain=v1", "-z"], cwd=repo, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout
        diff = subprocess.run(
            ["git", "diff", "--binary", "HEAD"], cwd=repo, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise BenchmarkRuntimeError("cannot observe exact candidate Git identity") from exc
    return commit, not status and not diff, "CLEAN" if not status and not diff else hashlib.sha256(status + b"\0" + diff).hexdigest()


def _cli_build_hash(repo: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted((repo / "ctf_os").rglob("*.py")):
        if path.is_symlink():
            raise BenchmarkRuntimeError("CLI source tree contains a symlink")
        digest.update(path.relative_to(repo).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _docker_identity(*, required: bool = False) -> dict[str, Any]:
    try:
        value = subprocess.run(
            ["docker", "info", "--format", "{{json .}}"], check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15,
        ).stdout.strip()
        info = json.loads(value)
        return {
            "server_version": info.get("ServerVersion"),
            "operating_system": info.get("OperatingSystem"),
            "architecture": info.get("Architecture"),
            "container_runtime": info.get("DefaultRuntime"),
        }
    except Exception as exc:
        if required:
            raise BenchmarkRuntimeError("benchmark requires an observable Linux/amd64 Docker server") from exc
        return {"observation_status": "UNAVAILABLE", "reason": str(exc)[:500]}


def _validate_host_requirements(
    repo: Path, requirements: Mapping[str, Any], docker: Mapping[str, Any],
) -> dict[str, Any]:
    machine = platform.machine().lower()
    if platform.system() != "Linux" or machine not in {"x86_64", "amd64"}:
        raise BenchmarkRuntimeError("benchmark host must be Linux/amd64")
    cpus = os.cpu_count() or 0
    try:
        mem_kib = next(
            int(line.split()[1]) for line in Path("/proc/meminfo").read_text().splitlines()
            if line.startswith("MemTotal:")
        )
    except (OSError, StopIteration, ValueError) as exc:
        raise BenchmarkRuntimeError("benchmark cannot observe host RAM") from exc
    free_gib = shutil.disk_usage(repo).free / (1024 ** 3)
    if cpus < int(requirements["minimum_vcpu"]):
        raise BenchmarkRuntimeError("benchmark host does not meet the 16-vCPU minimum")
    if mem_kib / (1024 ** 2) < float(requirements["minimum_ram_gib"]):
        raise BenchmarkRuntimeError("benchmark host does not meet the 64-GiB RAM minimum")
    if free_gib < float(requirements["minimum_free_ssd_gib"]):
        raise BenchmarkRuntimeError("benchmark host does not meet the 200-GiB free SSD minimum")
    architecture = str(docker.get("architecture") or "").lower()
    operating_system = str(docker.get("operating_system") or "").lower()
    if architecture not in {"x86_64", "amd64"} or "linux" not in operating_system:
        raise BenchmarkRuntimeError("benchmark Docker server must be Linux/amd64")
    return {
        "cpu_count": cpus, "ram_gib": mem_kib / (1024 ** 2),
        "free_ssd_gib": free_gib, "machine": machine,
    }


def _verify_local_image_digest(digest: str) -> None:
    try:
        observed = subprocess.run(
            ["docker", "image", "inspect", digest, "--format", "{{.Id}}"],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise BenchmarkRuntimeError(f"benchmark image digest is not locally resolvable: {digest}") from exc
    if observed != digest:
        raise BenchmarkRuntimeError("Docker image identity differs from the content-addressed digest")


def _file_sha256(path: Path, label: str) -> str:
    if path.is_symlink() or not path.is_file():
        raise BenchmarkRuntimeError(f"{label} must be a regular non-symlink file")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _active_width_timeline(branches: list[Mapping[str, Any]]) -> list[int]:
    events = sorted(
        (event for branch in branches for event in branch["lifecycle_history"]),
        key=lambda row: (str(row["created_at"]), str(row["lineage_event_id"])),
    )
    active: set[str] = set(); widths: list[int] = []
    for event in events:
        key = str(event["lineage_branch_id"])
        if event["event"] == "RUNNING":
            active.add(key)
        elif event["event"] in {
            "STOP_REQUESTED", "NATIVE_STOP_RECORDED", "CHILD_TERMINAL_RESULT_RECORDED",
            "START_FAILED", "SUPERSEDED", "TERMINAL",
        }:
            active.discard(key)
        widths.append(len(active))
    return widths


def _branch_routing_observation(branch: Mapping[str, Any]) -> dict[str, Any]:
    start = branch.get("start_receipt") or branch.get("native_start_receipt")
    receipt = start if isinstance(start, Mapping) else {}
    classification = str(
        receipt.get("routing_classification")
        or ("LEGACY_UNROUTED" if not branch.get("routing_profile") else "RUNTIME_NOT_OBSERVABLE")
    )
    return {
        "run_id": branch.get("run_id"),
        "session_id": branch.get("session_id"),
        "routing_profile": branch.get("routing_profile", "LEGACY_UNROUTED"),
        "requested_model": receipt.get("requested_model", branch.get("requested_model")),
        "requested_reasoning": receipt.get(
            "requested_reasoning", branch.get("requested_reasoning"),
        ),
        "observed_model": receipt.get("observed_model"),
        "observed_reasoning": receipt.get("observed_reasoning"),
        "routing_classification": classification,
        "routing_matched": receipt.get("routing_matched", False),
        "solver_success": branch.get("status") in {
            "SUPPORTED", "COMPLETED", "FLAG_CANDIDATE",
        },
    }
