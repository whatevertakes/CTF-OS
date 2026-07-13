from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import subprocess

import pytest

from ctf_os.evidence import append_evidence, append_finding
from ctf_os.sandbox.resources import GIB, RESOURCE_PROFILES, ResourceError, admit, sandbox_gc, sandbox_status
from ctf_os.sandbox.runtime import SandboxError, SandboxSpec, build_run_argv, cleanup, execute, export_artifacts, stage_artifacts
import ctf_os.sandbox.resources as resources
import ctf_os.sandbox.runtime as runtime


def _metadata(branch_root: Path) -> dict[str, object]:
    return {
        "name": "ctf-os-demo-abc-recon-1234567890",
        "contest_slug": "demo",
        "challenge_id": "abc",
        "branch": "recon",
        "branch_root": str(branch_root),
        "labels": {
            "ctf-os": "true",
            "ctf-os.contest": "demo",
            "ctf-os.challenge_id": "abc",
            "ctf-os.branch": "recon",
        },
        "authorized_targets": [],
        "input_fingerprint": "fingerprint",
    }


def test_profiles_apply_limits_and_local_network_is_distinct(tmp_path: Path) -> None:
    source = tmp_path / "input"
    source.mkdir()
    spec = SandboxSpec(
        "demo", "abc", "recon", source, tmp_path / "challenge" / "workers" / "recon",
        resource_profile="light", service_network="ctf-os-net-demo-abc",
        local_endpoints=("http://chall:8080",),
    )
    assert (spec.memory, spec.cpus, spec.storage, spec.pids) == ("2g", 1.0, "1g", 128)
    argv = build_run_argv(spec)
    assert argv[argv.index("--network") + 1] == "ctf-os-net-demo-abc"
    assert "NET_ADMIN" not in argv
    assert "ctf-os.kind=sandbox" in argv
    assert "ctf-os.resource_profile=light" in argv

    with pytest.raises(SandboxError, match="separate sandboxes"):
        build_run_argv(
            SandboxSpec(
                "demo", "abc", "bad", source, tmp_path / "bad",
                targets=(object(),),  # type: ignore[arg-type]
                service_network="ctf-os-net-demo-abc", local_endpoints=("http://chall:8080",),
            )
        )


def test_admission_enforces_profile_and_host_memory(monkeypatch) -> None:
    base = {
        "active": [
            {"resource_profile": "standard", "memory_bytes": 4 * GIB},
            {"resource_profile": "standard", "memory_bytes": 4 * GIB},
        ],
        "reserved_memory_bytes": 8 * GIB,
        "admission_memory_budget_bytes": 24 * GIB,
    }
    monkeypatch.setattr(resources, "sandbox_status", lambda **kwargs: base)
    with pytest.raises(ResourceError, match="limit 2"):
        admit("standard")

    memory_limited = {**base, "active": [], "reserved_memory_bytes": 7 * GIB, "admission_memory_budget_bytes": 8 * GIB}
    monkeypatch.setattr(resources, "sandbox_status", lambda **kwargs: memory_limited)
    with pytest.raises(ResourceError, match="memory budget"):
        admit("light")


def test_status_and_gc_report_only_label_scoped_stale_sandboxes(monkeypatch) -> None:
    containers = [
        {"id": "running", "name": "one", "running": True, "status": "running", "resource_profile": "light", "memory_bytes": 2 * GIB},
        {"id": "stale", "name": "old", "running": False, "status": "exited", "resource_profile": "standard", "memory_bytes": 4 * GIB},
    ]
    monkeypatch.setattr(resources, "_list_managed_sandboxes", lambda **kwargs: containers)
    monkeypatch.setattr(resources, "_docker_memory_total", lambda docker: 16 * GIB)
    status = sandbox_status()
    assert status["active_count"] == 1
    assert [item["name"] for item in status["stale"]] == ["old"]
    calls: list[list[str]] = []
    monkeypatch.setattr(
        resources, "_run",
        lambda argv, timeout: calls.append(argv) or subprocess.CompletedProcess(argv, 0, "", ""),
    )
    result = sandbox_gc()
    assert result["removed"] == ["old"]
    assert calls == [["docker", "rm", "--force", "stale"]]


def test_execute_does_not_export_until_cleanup(monkeypatch, tmp_path: Path) -> None:
    branch = tmp_path / "challenge" / "workers" / "recon"
    branch.mkdir(parents=True)
    metadata = _metadata(branch)
    monkeypatch.setattr(
        runtime, "_run",
        lambda *args, **kwargs: subprocess.CompletedProcess([], 0, "ok", ""),
    )
    monkeypatch.setattr(runtime, "_export_artifacts", lambda *args, **kwargs: pytest.fail("unexpected export"))
    receipt = execute(metadata, ["true"], 10)
    assert receipt["exit_code"] == 0
    assert receipt["artifacts_exported"] is False


def test_explicit_export_records_receipt(monkeypatch, tmp_path: Path) -> None:
    branch = tmp_path / "challenge" / "workers" / "recon"
    branch.mkdir(parents=True)
    metadata = _metadata(branch)
    monkeypatch.setattr(
        runtime, "_export_artifacts",
        lambda *args, **kwargs: {"destination": str(branch / "artifacts"), "files": 2, "bytes": 10},
    )
    result = export_artifacts(metadata)
    assert result["files"] == 2
    row = json.loads((tmp_path / "challenge" / "evidence.log").read_text().splitlines()[0])
    assert row["event"] == "sandbox_export" and row["bytes"] == 10


def test_replay_artifacts_are_staged_by_root_docker_operation(monkeypatch, tmp_path: Path) -> None:
    branch = tmp_path / "challenge" / "workers" / "recon"
    branch.mkdir(parents=True)
    exploit = tmp_path / "challenge" / "exploit"
    exploit.mkdir()
    (exploit / "solve.py").write_text("print('flag')")
    metadata = _metadata(branch)
    calls: list[list[str]] = []
    streams: list[tuple[Path, str, str]] = []
    monkeypatch.setattr(
        runtime, "_run",
        lambda argv, timeout: calls.append(list(argv)) or subprocess.CompletedProcess(argv, 0, "", ""),
    )
    monkeypatch.setattr(runtime, "_stream_tree_to_container", lambda source, container, target, **kwargs: streams.append((source, container, target)))
    result = stage_artifacts(metadata, exploit, "exploit")
    assert result["destination"] == "/artifacts/exploit"
    assert streams == [(exploit, metadata["name"], "/artifacts/exploit")]
    assert any(call[1:5] == ["exec", "--user", "1001:1001", metadata["name"]] for call in calls)

    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(SandboxError, match="selected challenge workspace"):
        stage_artifacts(metadata, outside)


def test_cleanup_exports_before_label_scoped_removal(monkeypatch, tmp_path: Path) -> None:
    branch = tmp_path / "challenge" / "workers" / "recon"
    branch.mkdir(parents=True)
    metadata = _metadata(branch)
    calls: list[str] = []

    def fake_run(argv, timeout):
        calls.append(" ".join(argv))
        if argv[1] == "inspect":
            return subprocess.CompletedProcess(argv, 0, json.dumps(metadata["labels"]), "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(runtime, "_run", fake_run)
    monkeypatch.setattr(
        runtime, "_export_artifacts",
        lambda *args, **kwargs: calls.append("export") or {"destination": "x", "files": 1, "bytes": 4},
    )
    result = cleanup(metadata)
    assert result["removed"] is True
    assert calls.index("export") < next(index for index, call in enumerate(calls) if " rm --force " in f" {call} ")


def test_evidence_and_findings_are_locked_under_concurrency(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence.log"

    def write(index: int) -> None:
        append_evidence(evidence, "parallel", {"index": index, "blob": "x" * 1000})
        append_finding(tmp_path, f"b{index}", f"finding-{index}", f"receipt-{index}", "supported")

    with ThreadPoolExecutor(max_workers=12) as pool:
        list(pool.map(write, range(60)))

    evidence_rows = [json.loads(line) for line in evidence.read_text().splitlines()]
    finding_rows = [json.loads(line) for line in (tmp_path / "findings.jsonl").read_text().splitlines()]
    markdown = (tmp_path / "FINDINGS.md").read_text()
    assert {row["index"] for row in evidence_rows} == set(range(60))
    assert {row["branch"] for row in finding_rows} == {f"b{i}" for i in range(60)}
    assert markdown.count("\n## finding-") == 60


def test_profile_contract_values() -> None:
    assert set(RESOURCE_PROFILES) == {"light", "standard", "heavy", "large-forensic"}
    assert RESOURCE_PROFILES["heavy"].memory_bytes >= 8 * GIB
    assert RESOURCE_PROFILES["large-forensic"].storage_bytes >= 8 * GIB
