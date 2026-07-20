"""Deterministic host-side benchmark health and resource telemetry.

This module never creates, controls, or discovers model sessions.  Every API is
bound to an exact benchmark run directory and records only directly observed
host/process data.  Unavailable attribution remains explicit missingness.
"""

from __future__ import annotations

from collections.abc import Sequence
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import time
from typing import Any

from .attempts import canonical_json
from .benchmark_manifest import record_resource_observation, record_target_health
from .race_lineage import lineage_state
from .workspace import atomic_json, utc_now
from .workspace import append_jsonl_fsync, read_jsonl_strict


TELEMETRY_SCHEMA_VERSION = 1


class BenchmarkTelemetryError(ValueError):
    pass


def start_resource_telemetry(
    run: Path, *, tracked_pids: Sequence[int] = (),
    network_namespace_pid: int | None = None,
    container_ids: Sequence[str] = (),
) -> dict[str, Any]:
    """Record an immutable baseline for explicitly supplied process IDs."""

    manifest = _manifest_for_exact_run(run)
    pids = _normalize_pids(tracked_pids)
    network_pid = _normalize_pids([network_namespace_pid])[0] if network_namespace_pid else None
    containers = _normalize_container_ids(container_ids)
    snapshot = _resource_snapshot(pids, network_pid=network_pid, container_ids=containers)
    baseline = {
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "challenge_instance_id": manifest["challenge_instance_id"],
        "attempt_id": manifest["attempt_id"],
        "run_id": manifest["run_id"],
        "tracked_pids": pids, "include_descendants": True,
        "network_namespace_pid": network_pid,
        "network_attribution": "DEDICATED_NETWORK_NAMESPACE" if network_pid else "NOT_CONFIGURED",
        "container_ids": containers,
        "started_at": utc_now(),
        "monotonic_started": snapshot["monotonic"],
        "processes": snapshot["processes"],
        "initial_snapshot": snapshot,
        "host_rusage": _rusage_snapshot(),
        "model_session_lifecycle_owned": False,
    }
    path = run / "BENCHMARK_TELEMETRY.json"
    if path.is_symlink() or path.exists():
        raise BenchmarkTelemetryError("benchmark telemetry baseline already exists or is unsafe")
    atomic_json(path, baseline)
    return baseline


def sample_resource_telemetry(run: Path) -> dict[str, Any]:
    """Append one directly observed process/namespace/container sample."""

    manifest = _manifest_for_exact_run(run)
    baseline = _safe_json(run / "BENCHMARK_TELEMETRY.json", "benchmark telemetry baseline")
    _require_identity(baseline, manifest)
    if baseline.get("finished_at") is not None:
        raise BenchmarkTelemetryError("benchmark telemetry is already finished")
    snapshot = _resource_snapshot(
        _normalize_pids(baseline.get("tracked_pids") or []),
        network_pid=baseline.get("network_namespace_pid"),
        container_ids=_normalize_container_ids(baseline.get("container_ids") or []),
    )
    row = {
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "challenge_instance_id": manifest["challenge_instance_id"],
        "attempt_id": manifest["attempt_id"], "run_id": manifest["run_id"],
        **snapshot,
    }
    append_jsonl_fsync(
        run / "BENCHMARK_TELEMETRY_SAMPLES.jsonl", row,
        label="benchmark telemetry sample ledger",
    )
    return row


def run_resource_telemetry_monitor(
    run: Path, *, duration_seconds: float, cadence_seconds: float = 1.0,
    tracked_pids: Sequence[int] = (), network_namespace_pid: int | None = None,
    container_ids: Sequence[str] = (),
) -> dict[str, Any]:
    """Sample one exact attempt without owning any tracked process lifecycle."""

    if duration_seconds < 0 or cadence_seconds <= 0 or cadence_seconds > 60:
        raise BenchmarkTelemetryError("resource telemetry duration/cadence is invalid")
    baseline = start_resource_telemetry(
        run, tracked_pids=tracked_pids, network_namespace_pid=network_namespace_pid,
        container_ids=container_ids,
    )
    deadline = time.monotonic() + duration_seconds
    next_sample = min(deadline, time.monotonic() + cadence_seconds)
    while next_sample < deadline:
        wait = next_sample - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        sample_resource_telemetry(run)
        next_sample += cadence_seconds
    wait = deadline - time.monotonic()
    if wait > 0:
        time.sleep(wait)
    sample_resource_telemetry(run)
    finished = finish_resource_telemetry(run)
    return {
        "run_id": run.name, "attempt_id": baseline["attempt_id"],
        "duration_seconds": duration_seconds, "cadence_seconds": cadence_seconds,
        "model_session_lifecycle_owned": False, "telemetry": finished,
    }


def finish_resource_telemetry(run: Path) -> dict[str, Any]:
    """Finish telemetry without replacing unavailable values with zero."""

    manifest = _manifest_for_exact_run(run)
    path = run / "BENCHMARK_TELEMETRY.json"
    baseline = _safe_json(path, "benchmark telemetry baseline")
    _require_identity(baseline, manifest)
    if baseline.get("finished_at") is not None:
        return baseline

    pids = _normalize_pids(baseline.get("tracked_pids") or [])
    network_pid = baseline.get("network_namespace_pid")
    containers = _normalize_container_ids(baseline.get("container_ids") or [])
    final_snapshot = _resource_snapshot(pids, network_pid=network_pid, container_ids=containers)
    final_processes = final_snapshot["processes"]
    final_rusage = _rusage_snapshot()
    finished_at = utc_now()
    elapsed = max(0.0, time.monotonic() - float(baseline["monotonic_started"]))
    baseline.update({
        "finished_at": finished_at,
        "elapsed_seconds": elapsed,
        "final_processes": final_processes,
        "final_snapshot": final_snapshot,
        "final_host_rusage": final_rusage,
    })

    samples = [baseline["initial_snapshot"]] + [
        {key: value for key, value in row.items() if key not in {
            "schema_version", "challenge_instance_id", "attempt_id", "run_id",
        }}
        for row in read_jsonl_strict(
            run / "BENCHMARK_TELEMETRY_SAMPLES.jsonl", "benchmark telemetry sample ledger",
        )
    ] + [final_snapshot]
    process_histories: dict[str, list[dict[str, Any]]] = {}
    for snapshot in samples:
        for pid, value in snapshot.get("processes", {}).items():
            process_histories.setdefault(pid, []).append(value)
    if process_histories:
        cpu_seconds = sum(
            max(0.0, max(row["cpu_seconds"] for row in values) - min(row["cpu_seconds"] for row in values))
            for values in process_histories.values()
        )
        ram_integral = _integrate_samples(samples, "processes", lambda rows: sum(
            int(value["rss_bytes"]) for value in rows.values()
        )) / (1024 ** 3)
        peak = max(
            int(row["rss_bytes"])
            for values in process_histories.values() for row in values
        )
        record_resource_observation(run, "cpu_seconds", value=cpu_seconds)
        record_resource_observation(run, "ram_peak_bytes", value=peak)
        record_resource_observation(run, "ram_gib_seconds", value=ram_integral)
    else:
        for field in ("cpu_seconds", "ram_peak_bytes", "ram_gib_seconds"):
            record_resource_observation(
                run, field, observation_status="NOT_OBSERVABLE",
                reason="no explicitly tracked process remained observable at both telemetry boundaries",
            )

    network = [snapshot["network"] for snapshot in samples if snapshot.get("network") is not None]
    if len(network) >= 2:
        record_resource_observation(run, "network_rx_bytes", value=max(0, max(row["rx_bytes"] for row in network) - min(row["rx_bytes"] for row in network)))
        record_resource_observation(run, "network_tx_bytes", value=max(0, max(row["tx_bytes"] for row in network) - min(row["tx_bytes"] for row in network)))
    else:
        for field in ("network_rx_bytes", "network_tx_bytes"):
            record_resource_observation(
                run, field, observation_status="NOT_OBSERVABLE",
                reason="no dedicated network-namespace counter remained observable across samples",
            )
    if containers and all(snapshot.get("containers") is not None for snapshot in samples):
        lifetime = _integrate_samples(samples, "containers", lambda rows: sum(
            1 for value in rows.values() if value.get("running") is True
        ))
        record_resource_observation(run, "container_lifetime_seconds", value=lifetime)
    else:
        record_resource_observation(
            run, "container_lifetime_seconds", observation_status="NOT_OBSERVABLE",
            reason="no exact benchmark container identity remained observable across samples",
        )

    lineage = lineage_state(run)
    child_count = sum(
        1 for branch in lineage["branches"]
        if any(event["event"] == "NATIVE_STARTED" for event in branch["lifecycle_history"])
    )
    maximum_width = _maximum_active_width(lineage["branches"])
    record_resource_observation(run, "child_session_count", value=child_count)
    record_resource_observation(run, "maximum_active_width", value=maximum_width)
    atomic_json(path, baseline)
    return baseline


def run_target_health_monitor(
    run: Path,
    *,
    probe_argv: Sequence[str],
    endpoint_revision: int,
    duration_seconds: float,
    cadence_seconds: float = 60.0,
    timeout_seconds: float = 10.0,
    semantic_success_token: str | None = None,
) -> dict[str, Any]:
    """Probe at run start, each cadence boundary, and run end using direct argv.

    The caller supplies a deterministic health command (typically a local replay
    probe).  No shell, model API, native-session operation, or ambient environment
    capture is involved.
    """

    manifest = _manifest_for_exact_run(run)
    argv = _validate_probe_argv(probe_argv)
    if endpoint_revision < 0 or duration_seconds < 0 or cadence_seconds <= 0 or timeout_seconds <= 0:
        raise BenchmarkTelemetryError("health monitor timing/revision values are invalid")
    start_monotonic = time.monotonic()
    deadline = start_monotonic + duration_seconds
    rows: list[dict[str, Any]] = []

    rows.append(_run_health_probe(
        run, manifest=manifest, argv=argv, endpoint_revision=endpoint_revision,
        timeout_seconds=timeout_seconds, semantic_success_token=semantic_success_token,
        phase="RUN_START",
    ))
    next_probe = start_monotonic + cadence_seconds
    while next_probe < deadline:
        wait = next_probe - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        rows.append(_run_health_probe(
            run, manifest=manifest, argv=argv, endpoint_revision=endpoint_revision,
            timeout_seconds=timeout_seconds, semantic_success_token=semantic_success_token,
            phase="PERIODIC",
        ))
        next_probe += cadence_seconds
    wait = deadline - time.monotonic()
    if wait > 0:
        time.sleep(wait)
    rows.append(_run_health_probe(
        run, manifest=manifest, argv=argv, endpoint_revision=endpoint_revision,
        timeout_seconds=timeout_seconds, semantic_success_token=semantic_success_token,
        phase="RUN_END",
    ))
    return {
        "run_id": run.name, "attempt_id": manifest["attempt_id"],
        "probe_count": len(rows), "cadence_seconds": cadence_seconds,
        "duration_seconds": duration_seconds, "model_session_launched": False,
        "receipts": rows,
    }


def _run_health_probe(
    run: Path, *, manifest: dict[str, Any], argv: list[str], endpoint_revision: int,
    timeout_seconds: float, semantic_success_token: str | None, phase: str,
) -> dict[str, Any]:
    started_at = utc_now()
    status = "UNHEALTHY"
    semantic = "COMMAND_FAILED"
    returncode: int | None = None
    stdout = b""; stderr = b""
    try:
        completed = subprocess.run(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=timeout_seconds, env=_minimal_environment(),
        )
        returncode = completed.returncode
        stdout, stderr = completed.stdout, completed.stderr
        token_ok = semantic_success_token is None or semantic_success_token.encode() in stdout
        if returncode == 0 and token_ok:
            status = "HEALTHY"; semantic = "PASS"
        elif returncode == 0:
            semantic = "SEMANTIC_TOKEN_MISSING"
    except subprocess.TimeoutExpired as exc:
        status = "TIMEOUT"; semantic = "PROBE_TIMEOUT"
        stdout = bytes(exc.stdout or b""); stderr = bytes(exc.stderr or b"")
    except OSError as exc:
        status = "PROBE_ERROR"; semantic = f"EXEC_ERROR:{type(exc).__name__}"
        stderr = str(exc).encode("utf-8", errors="replace")
    ended_at = utc_now()
    material = {
        "schema_version": 1,
        "challenge_instance_id": manifest["challenge_instance_id"],
        "attempt_id": manifest["attempt_id"], "run_id": manifest["run_id"],
        "phase": phase, "started_at": started_at, "ended_at": ended_at,
        "status": status, "semantic_health_result": semantic,
        "endpoint_revision": endpoint_revision,
        "command_digest": hashlib.sha256(canonical_json(argv)).hexdigest(),
        "returncode": returncode,
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(), "stdout_bytes": len(stdout),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(), "stderr_bytes": len(stderr),
        "model_session_lifecycle_owned": False,
    }
    receipt_id = "target-health-" + hashlib.sha256(canonical_json(material)).hexdigest()
    receipt = {**material, "probe_receipt_id": receipt_id}
    receipt_dir = run / "target-health-receipts"
    receipt_dir.mkdir(mode=0o700, exist_ok=True)
    receipt_path = receipt_dir / f"{receipt_id}.json"
    if receipt_path.is_symlink():
        raise BenchmarkTelemetryError("target health receipt path is unsafe")
    atomic_json(receipt_path, receipt)
    record_target_health(
        run, started_at=started_at, ended_at=ended_at, status=status,
        probe_receipt_id=receipt_id, endpoint_revision=endpoint_revision,
        semantic_health_result=semantic, phase=phase,
    )
    return {**receipt, "receipt_path": str(receipt_path)}


def _manifest_for_exact_run(run: Path) -> dict[str, Any]:
    if run.is_symlink() or not run.is_dir() or run.name in {"", ".", ".."}:
        raise BenchmarkTelemetryError("exact benchmark run directory is unsafe")
    manifest = _safe_json(run / "RUN_MANIFEST.json", "benchmark run manifest")
    if manifest.get("run_id") != run.name or manifest.get("active_run_pointer_used") is not False:
        raise BenchmarkTelemetryError("telemetry requires an exact benchmark run, never ACTIVE_RUN")
    return manifest


def _require_identity(value: dict[str, Any], manifest: dict[str, Any]) -> None:
    for field in ("challenge_instance_id", "attempt_id", "run_id"):
        if value.get(field) != manifest.get(field):
            raise BenchmarkTelemetryError(f"telemetry {field} belongs to another attempt")


def _normalize_pids(values: Sequence[int]) -> list[int]:
    result: list[int] = []
    for value in values:
        try:
            pid = int(value)
        except (TypeError, ValueError) as exc:
            raise BenchmarkTelemetryError("tracked PID must be an integer") from exc
        if pid <= 0:
            raise BenchmarkTelemetryError("tracked PID must be positive")
        if pid not in result:
            result.append(pid)
    return sorted(result)


def _process_snapshot(pids: Sequence[int]) -> dict[str, Any]:
    clock_ticks = os.sysconf("SC_CLK_TCK")
    page_size = os.sysconf("SC_PAGE_SIZE")
    rows: dict[str, Any] = {}
    for pid in _expand_descendants(pids):
        try:
            # The comm field can contain spaces/parentheses, so split after its final ') '.
            raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
            tail = raw[raw.rfind(") ") + 2 :].split()
            utime, stime, rss_pages = int(tail[11]), int(tail[12]), int(tail[21])
            rows[str(pid)] = {
                "cpu_seconds": (utime + stime) / clock_ticks,
                "rss_bytes": rss_pages * page_size,
                "observed_at": utc_now(),
            }
        except (OSError, ValueError, IndexError):
            continue
    return rows


def _resource_snapshot(
    pids: Sequence[int], *, network_pid: int | None, container_ids: Sequence[str],
) -> dict[str, Any]:
    return {
        "observed_at": utc_now(), "monotonic": time.monotonic(),
        "processes": _process_snapshot(pids),
        "network": _network_snapshot(int(network_pid)) if network_pid else None,
        "containers": _container_snapshot(container_ids) if container_ids else None,
    }


def _expand_descendants(roots: Sequence[int]) -> list[int]:
    selected = set(roots)
    changed = True
    while changed:
        changed = False
        for path in Path("/proc").glob("[0-9]*/stat"):
            try:
                raw = path.read_text(encoding="utf-8")
                tail = raw[raw.rfind(") ") + 2 :].split()
                pid = int(path.parent.name); parent = int(tail[1])
            except (OSError, ValueError, IndexError):
                continue
            if parent in selected and pid not in selected:
                selected.add(pid); changed = True
    return sorted(selected)


def _network_snapshot(pid: int) -> dict[str, int] | None:
    try:
        lines = Path(f"/proc/{pid}/net/dev").read_text(encoding="utf-8").splitlines()[2:]
        rx = tx = 0
        for line in lines:
            _interface, values = line.split(":", 1)
            fields = values.split(); rx += int(fields[0]); tx += int(fields[8])
        return {"rx_bytes": rx, "tx_bytes": tx}
    except (OSError, ValueError, IndexError):
        return None


def _container_snapshot(container_ids: Sequence[str]) -> dict[str, Any] | None:
    rows: dict[str, Any] = {}
    for container_id in container_ids:
        try:
            raw = subprocess.run(
                ["docker", "inspect", container_id, "--format", "{{json .State}}"],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=10,
            ).stdout
            state = json.loads(raw)
            rows[container_id] = {
                "running": state.get("Running") is True,
                "pid": state.get("Pid"), "started_at": state.get("StartedAt"),
                "finished_at": state.get("FinishedAt"),
            }
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError):
            return None
    return rows


def _integrate_samples(
    samples: Sequence[dict[str, Any]], field: str, value_fn: Any,
) -> float:
    total = 0.0
    ordered = sorted(samples, key=lambda row: float(row["monotonic"]))
    for before, after in zip(ordered, ordered[1:]):
        left = before.get(field); right = after.get(field)
        if left is None or right is None:
            continue
        seconds = max(0.0, float(after["monotonic"]) - float(before["monotonic"]))
        total += (float(value_fn(left)) + float(value_fn(right))) * 0.5 * seconds
    return total


def _normalize_container_ids(values: Sequence[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        identity = str(value).strip()
        if not identity or len(identity) > 128 or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for character in identity):
            raise BenchmarkTelemetryError("container identity is unsafe")
        if identity not in result:
            result.append(identity)
    return sorted(result)


def _rusage_snapshot() -> dict[str, Any]:
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {
        "child_user_cpu_seconds": usage.ru_utime,
        "child_system_cpu_seconds": usage.ru_stime,
        "child_max_rss_platform_units": usage.ru_maxrss,
    }


def _maximum_active_width(branches: Sequence[dict[str, Any]]) -> int:
    events = sorted(
        (event for branch in branches for event in branch["lifecycle_history"]),
        key=lambda event: (str(event["created_at"]), str(event["lineage_event_id"])),
    )
    running: set[str] = set(); maximum = 0
    for event in events:
        branch = str(event["lineage_branch_id"])
        if event["event"] == "RUNNING":
            running.add(branch)
        elif event["event"] in {
            "STOP_REQUESTED", "NATIVE_STOP_RECORDED", "CHILD_TERMINAL_RESULT_RECORDED",
            "START_FAILED", "SUPERSEDED", "TERMINAL",
        }:
            running.discard(branch)
        maximum = max(maximum, len(running))
    return maximum


def _validate_probe_argv(values: Sequence[str]) -> list[str]:
    argv = [str(value) for value in values]
    if argv and argv[0] == "--":
        argv.pop(0)
    if not argv or any("\x00" in value for value in argv):
        raise BenchmarkTelemetryError("target health probe requires safe direct argv")
    lowered = " ".join(argv).lower()
    if any(marker in lowered for marker in ("authorization:", "password=", "token=", "api_key=")):
        raise BenchmarkTelemetryError("target health argv must not contain credentials")
    return argv


def _minimal_environment() -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
    }


def _safe_json(path: Path, label: str) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise BenchmarkTelemetryError(f"{label} is missing or unsafe")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BenchmarkTelemetryError(f"{label} is malformed") from exc
    if not isinstance(value, dict):
        raise BenchmarkTelemetryError(f"{label} must be an object")
    return value
