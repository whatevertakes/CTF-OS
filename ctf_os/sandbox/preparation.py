"""Shared, side-effect-light preparation for worker and manual-rescue sandboxes."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from ..preflight import prepared_input_bytes, prepared_tree_fingerprint
from ..resources.scheduler import ResourceLedger, detect_capacity, detect_gpus, infer_workload
from ..service import ServiceActor, ServiceSpec, service_inspect
from ..workspace import challenge_workspace
from .network import parse_remotes, resolve_targets
from .runtime import SandboxSpec


SUPPORTED_IMAGES = frozenset({
    "pwn", "web", "rev", "crypto", "forensic", "misc", "osint", "ai", "cloud",
})
RESCUE_SERVICE_ERROR = (
    "External rescue requires the Sol-owned challenge service to be running. "
    "Return to the current Sol session, start the managed service, then rerun rescue-prepare."
)


@dataclass(frozen=True, slots=True)
class PreparedSandbox:
    spec: SandboxSpec
    attachment_service: ServiceSpec | None
    service_context: Mapping[str, object]


def validate_prepared_input(
    workspace: Path,
    record: Mapping[str, object],
    *,
    fingerprint_reader: Callable[[Path], str] = prepared_tree_fingerprint,
) -> Path:
    """Return the exact prepared tree after the same checks used by sandbox-create."""

    input_path = workspace / "input"
    if input_path.is_symlink() or not input_path.is_dir():
        raise ValueError(
            "prepared challenge input is missing or unsafe; run same-session preparation again"
        )
    expected_source = input_path.resolve()
    try:
        expected_source.relative_to(workspace.resolve())
    except ValueError as exc:
        raise ValueError("prepared challenge input escapes its challenge workspace") from exc
    declared = record.get("prepared_input")
    if not isinstance(declared, str) or Path(declared).resolve() != expected_source:
        raise ValueError(
            "preflight record prepared_input is outside the selected challenge workspace"
        )
    if record.get("prepared_fingerprint") != fingerprint_reader(input_path):
        raise ValueError(
            "prepared challenge input changed after preparation; run same-session preparation again"
        )
    return expected_source


def build_service_spec(
    manifest: Any,
    challenge: Any,
    record: Mapping[str, object],
    solve_root: Path,
) -> ServiceSpec:
    plan = record.get("service_plan")
    if not isinstance(plan, Mapping) or not plan.get("kind"):
        raise ValueError("challenge preparation found no Dockerfile/Compose service plan")
    return ServiceSpec(
        contest_slug=str(manifest.slug), challenge_id=str(challenge.id),
        source=challenge_workspace(solve_root) / "input", workspace=solve_root,
        service_plan=dict(plan),
    )


def prepare_sandbox_spec(
    *,
    repo_root: Path,
    manifest: Any,
    challenge: Any,
    record: Mapping[str, object],
    workspace: Path,
    solve_root: Path,
    branch: str,
    branch_root: Path,
    session_id: str,
    parent_session_id: str,
    session_role: str,
    image_override: str | None = None,
    resource_profile_override: str | None = None,
    require_service: bool = False,
    require_running_managed_service: bool = False,
    workspace_mode: str = "tmpfs",
    run_id: str | None = None,
    rescue_attempt_id: str | None = None,
    external_solver: bool = False,
    solver_family: str | None = None,
    session_kind: str = "native-worker",
    requested_lead_model: str | None = None,
    allow_scheduler_rebalance: bool = True,
    prepared_fingerprint_reader: Callable[[Path], str] = prepared_tree_fingerprint,
    service_inspector: Callable[..., dict[str, object]] = service_inspect,
    service_actor: ServiceActor | None = None,
    gpu_detector: Callable[[], Mapping[str, object]] = detect_gpus,
) -> PreparedSandbox:
    """Build one SandboxSpec without starting a container or service lifecycle."""

    if record.get("status") != "READY":
        raise ValueError(f"challenge is not READY: {record.get('blockers')}")
    source = validate_prepared_input(
        workspace, record, fingerprint_reader=prepared_fingerprint_reader,
    )
    category = str(challenge.category)
    image = image_override or str(
        record.get("recommended_image")
        or f"ctf-os-sandbox:{category if category in SUPPORTED_IMAGES else 'base'}"
    )
    profile = resource_profile_override or str(
        record.get("recommended_resource_profile") or "standard"
    )
    targets = resolve_targets(parse_remotes(challenge.remotes))
    service_network: str | None = None
    attachment_service: ServiceSpec | None = None
    endpoints: tuple[str, ...] = ()
    service_context: dict[str, object] = {
        "exists": False, "state": "UNAVAILABLE", "attach_only": True,
        "lifecycle_owner": parent_session_id,
    }
    plan = record.get("service_plan")
    managed = isinstance(plan, Mapping) and plan.get("kind") in {"dockerfile", "compose"}
    if managed:
        service = build_service_spec(manifest, challenge, record, solve_root)
        inspection = service_inspector(
            service,
            actor=service_actor or ServiceActor(
                session_id=parent_session_id, role="sol",
                parent_session_id=parent_session_id,
            ),
        )
        owner = inspection.get("ownership") if isinstance(inspection.get("ownership"), Mapping) else {}
        containers = inspection.get("containers") if isinstance(inspection.get("containers"), list) else []
        network = inspection.get("network") if isinstance(inspection.get("network"), Mapping) else {}
        active = (
            owner.get("state") == "RUNNING" and bool(containers)
            and all(
                item.get("state") == "running"
                for item in containers if isinstance(item, Mapping)
            )
            and network.get("owned") is True and network.get("internal") is True
        )
        service_context = {
            "exists": bool(owner), "state": owner.get("state", "UNOWNED"),
            "alias": service.stable_alias, "network": service.network,
            "lifecycle_owner": owner.get("owner_session_id"), "attach_only": True,
        }
        if active:
            if owner.get("owner_session_id") != parent_session_id:
                raise ValueError(
                    f"managed service owner mismatch: expected {parent_session_id}, "
                    f"found {owner.get('owner_session_id')}"
                )
            metadata = inspection.get("metadata") if isinstance(inspection.get("metadata"), Mapping) else {}
            endpoint_rows = (
                metadata.get("service_endpoints")
                if isinstance(metadata.get("service_endpoints"), list) else []
            )
            endpoints = tuple(
                str(item["target"])
                for item in endpoint_rows
                if isinstance(item, Mapping) and item.get("target")
            )
            if not endpoints:
                raise ValueError("active managed service has no stable endpoint metadata")
            targets = ()
            service_network = service.network
            attachment_service = service
            service_context.update({
                "endpoints": endpoint_rows,
                "service_url": endpoints[0],
                "instructions": (
                    "Managed service is already running. Connect and run PoCs only; "
                    "the parent Sol session owns its lifecycle."
                ),
            })
        elif require_running_managed_service:
            raise ValueError(RESCUE_SERVICE_ERROR)
        elif require_service or owner.get("state") == "RUNNING" or bool(containers):
            reasons: list[str] = []
            if not owner:
                reasons.append("owner missing")
            if owner and owner.get("state") != "RUNNING":
                reasons.append("service not running")
            if owner.get("state") == "RUNNING" and not containers:
                reasons.append("service container missing")
            if containers and not all(
                item.get("state") == "running"
                for item in containers if isinstance(item, Mapping)
            ):
                reasons.append("service container not running")
            if network.get("exists") is not True:
                reasons.append("network missing")
            elif network.get("owned") is not True:
                reasons.append("network is not owned")
            elif network.get("internal") is not True:
                reasons.append("network is not internal")
            raise ValueError(
                "managed service attachment failed: "
                + ", ".join(reasons or ["service unavailable"])
            )
    elif require_service or require_running_managed_service:
        raise ValueError(
            RESCUE_SERVICE_ERROR if require_running_managed_service else
            "managed service attachment failed: challenge preparation has no service plan"
        )

    resource_state = ResourceLedger(solve_root).load()
    request_raw = resource_state.get("requests", {}).get(session_id)
    allocation = resource_state.get("allocations", {}).get(session_id)
    if (
        allow_scheduler_rebalance
        and isinstance(request_raw, dict) and not isinstance(allocation, dict)
    ):
        scheduler_plan = ResourceLedger(solve_root).rebalance(detect_capacity(workspace=repo_root))
        allocation = scheduler_plan.get("allocations", {}).get(session_id)
        if not isinstance(allocation, dict):
            waiting = next((
                row for row in scheduler_plan.get("waiting", [])
                if row.get("session_id") == session_id
            ), {})
            raise ValueError(
                "resource scheduler cannot admit sandbox minimum: "
                + str(waiting.get("reason", "insufficient budget"))
            )
    inferred = infer_workload(
        files=[
            str(item.get("path", ""))
            for item in record.get("files", []) if isinstance(item, Mapping)
        ],
        role=branch, category=category,
        override=(
            "external-rescue" if session_kind == "external-rescue" else
            str(request_raw.get("workload_class"))
            if isinstance(request_raw, dict) else None
        ),
    )
    state = _load_state(solve_root)
    gpu_device = (
        int(allocation["gpu_device"])
        if isinstance(allocation, dict) and allocation.get("gpu_device") is not None else None
    )
    request_gpu = bool(
        isinstance(request_raw, dict)
        and (request_raw.get("gpu_required") or request_raw.get("gpu_preferred"))
    )
    if isinstance(allocation, dict):
        # A committed scheduler allocation is authoritative, including an
        # explicit preferred-GPU CPU fallback.
        gpu_enabled = gpu_device is not None
        if (
            isinstance(request_raw, dict) and request_raw.get("gpu_required")
            and not gpu_enabled
        ):
            raise ValueError(
                "resource scheduler cannot admit sandbox minimum: required GPU "
                "was not assigned"
            )
        gpu_requested = request_gpu or gpu_enabled
        gpu_backend = "nvidia" if gpu_enabled else None
        gpu_fallback = (
            None if gpu_enabled else str(allocation.get("gpu_fallback") or "CPU")
        )
    else:
        gpu = gpu_detector()
        gpu_enabled = bool(gpu.get("available"))
        if (
            isinstance(request_raw, dict) and request_raw.get("gpu_required")
            and not gpu_enabled
        ):
            raise ValueError(
                "resource scheduler cannot admit sandbox minimum: required GPU "
                + str(gpu.get("reason") or "runtime/device unavailable")
            )
        gpu_requested = request_gpu or gpu_enabled
        gpu_backend = str(gpu.get("backend") or "nvidia") if gpu_enabled else None
        gpu_fallback = None if gpu_enabled else "CPU"
    spec = SandboxSpec(
        contest_slug=str(manifest.slug), challenge_id=str(challenge.id), branch=branch,
        source=source, branch_root=branch_root,
        input_fingerprint=str(record["source_fingerprint"]),
        target_revision=int(state.get("target_revision") or 1),
        input_bytes=prepared_input_bytes(record),
        targets=targets, image=image, resource_profile=profile,
        service_network=service_network, local_endpoints=endpoints,
        session_id=session_id, parent_session_id=parent_session_id,
        session_role=session_role, service_context=service_context,
        category=category,
        memory=str(allocation["memory_bytes"]) if isinstance(allocation, dict) else None,
        cpus=float(allocation["cpus"]) if isinstance(allocation, dict) else None,
        storage=str(allocation["storage_bytes"]) if isinstance(allocation, dict) else None,
        workload_class=str(inferred["workload_class"]),
        resource_priority=(
            str(request_raw.get("priority", "NORMAL"))
            if isinstance(request_raw, dict) else "NORMAL"
        ),
        resource_request_override=request_raw if isinstance(request_raw, dict) else None,
        gpu_enabled=gpu_enabled, gpu_device=gpu_device,
        gpu_requested=gpu_requested, gpu_backend=gpu_backend,
        gpu_fallback=gpu_fallback,
        workspace_mode=workspace_mode, run_id=run_id,
        rescue_attempt_id=rescue_attempt_id, external_solver=external_solver,
        solver_family=solver_family, session_kind=session_kind,
        requested_lead_model=requested_lead_model,
    )
    return PreparedSandbox(spec, attachment_service, service_context)


def _load_state(solve_root: Path) -> dict[str, object]:
    path = solve_root / "STATE.json"
    if path.is_symlink() or not path.is_file():
        raise ValueError("run state is missing or unsafe during sandbox preparation")
    import json

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("run state is malformed during sandbox preparation") from exc
    if not isinstance(payload, dict):
        raise ValueError("run state must be an object during sandbox preparation")
    return payload
