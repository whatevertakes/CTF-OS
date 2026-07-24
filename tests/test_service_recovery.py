"""RH1 (cleanup-failed recovery) and RM3 (compose cleanup ownership) regressions."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from ctf_os.service import (
    ServiceActor,
    ServiceCleanupError,
    ServiceSpec,
    cleanup_service,
    prepare_service,
)

_PLAN = {
    "kind": "compose",
    "safe": True,
    "source": "compose.yml",
    "base_images": [],
    "runtime_images": ["ctf-os-sandbox:base"],
    "services": [{"name": "chall", "ports": [8000], "endpoints": ["http://chall:8000"], "build": False}],
    "review_reasons": [],
}


def _read_only_input(tmp_path: Path) -> Path:
    input_root = tmp_path / "input"
    input_root.mkdir()
    (input_root / "compose.yml").write_text(
        "services:\n  chall:\n    image: ctf-os-sandbox:base\n    expose: [8000]\n",
        encoding="utf-8",
    )
    for path in input_root.rglob("*"):
        path.chmod(0o444)
    input_root.chmod(0o555)
    return input_root


def test_failed_start_with_incomplete_rollback_raises_recovery(tmp_path: Path) -> None:
    input_root = _read_only_input(tmp_path)
    spec = ServiceSpec(
        run_id="run-rh1", challenge_id="challenge1", source=input_root,
        run_root=tmp_path / "run", plan=_PLAN,
    )

    def runner(argv, **kwargs):
        if argv[1:2] == ["info"]:
            return subprocess.CompletedProcess(argv, 0, json.dumps({"MemTotal": 32 * 1024**3, "NCPU": 16}), "")
        if argv[1:3] == ["image", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, "[]", "")
        if argv[1:3] == ["network", "inspect"]:
            return subprocess.CompletedProcess(argv, 0, json.dumps([{"Internal": True, "Labels": spec.labels}]), "")
        if "config" in argv and "--format" in argv:
            return subprocess.CompletedProcess(
                argv, 0, json.dumps({"services": {"chall": {"image": "ctf-os-sandbox:base"}}}), ""
            )
        if "up" in argv:
            return subprocess.CompletedProcess(argv, 1, "", "compose up failed")
        if "down" in argv:  # rollback also fails -> unrecovered
            return subprocess.CompletedProcess(argv, 1, "", "rollback down failed")
        if argv[1:3] == ["network", "rm"]:
            return subprocess.CompletedProcess(argv, 0, "", "")
        return subprocess.CompletedProcess(argv, 0, "[]", "")

    with pytest.raises(ServiceCleanupError) as raised:
        prepare_service(spec, actor=ServiceActor("root", "root"), runner=runner)
    assert raised.value.service["status"] == "CLEANUP_FAILED"
    assert raised.value.service["runtime"]["project"] == spec.project
    assert any("rollback down failed" in f for f in raised.value.failures)


def _compose_metadata(tmp_path: Path) -> dict:
    service_root = tmp_path / "run" / "service"
    service_root.mkdir(parents=True)
    return {
        "schema_version": 1,
        "status": "READY",
        "run_id": "run-rm3",
        "network": "",
        "labels": {"org.ctf-os.run-id": "run-rm3", "org.ctf-os.service-instance": "root"},
        "runtime": {
            "compose_files": [str(service_root / "compose.yml"), str(service_root / "compose.race.yml")],
            "project": "ctf-os-abc",
            "compose_env_file": str(service_root / "compose.empty.env"),
            "service_count": 1,
        },
        "metadata_path": str(service_root / "service.json"),
    }


def test_compose_cleanup_refuses_mismatched_labels(tmp_path: Path) -> None:
    metadata = _compose_metadata(tmp_path)

    def runner(argv, **kwargs):
        if "ps" in argv and "--all" in argv:
            return subprocess.CompletedProcess(argv, 0, "foreign-container\n", "")
        if argv[1:2] == ["inspect"]:
            return subprocess.CompletedProcess(argv, 0, json.dumps([{"Config": {"Labels": {"someone": "else"}}}]), "")
        raise AssertionError(f"cleanup must not run down: {argv}")

    result = cleanup_service(metadata, actor=ServiceActor("root", "root"), runner=runner)
    assert result["cleaned"] is False
    assert any("unowned or mismatched" in f for f in result["failures"])


def test_compose_cleanup_owned_project_tears_down(tmp_path: Path) -> None:
    metadata = _compose_metadata(tmp_path)
    down_called = []

    def runner(argv, **kwargs):
        if "ps" in argv and "--all" in argv:
            return subprocess.CompletedProcess(argv, 0, "owned-container\n", "")
        if argv[1:2] == ["inspect"]:
            return subprocess.CompletedProcess(argv, 0, json.dumps([{"Config": {"Labels": metadata["labels"]}}]), "")
        if "down" in argv:
            down_called.append(argv)
            return subprocess.CompletedProcess(argv, 0, "", "")
        return subprocess.CompletedProcess(argv, 0, "", "")

    result = cleanup_service(metadata, actor=ServiceActor("root", "root"), runner=runner)
    assert result["cleaned"] is True
    assert down_called
