from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

import pytest
from conftest import write_challenge

import ctf_os.agent_tools.__main__ as cli
import ctf_os.service as service_module
from ctf_os import images
from ctf_os.categories import CATEGORIES, canonical_category
from ctf_os.images import (
    expected_build_sha256,
    expected_lock_sha256,
    recommended_image,
    select_image,
)
from ctf_os.preflight import input_fingerprint, prepare_input, validate_prepared_input
from ctf_os.race import load_race
from ctf_os.sandbox.runtime import SandboxSpec, create
from ctf_os.workspace import WorkspaceError, create_run, resolve_run


def _image_result(image: str, *, available: set[str]) -> subprocess.CompletedProcess[str]:
    if image not in available:
        return subprocess.CompletedProcess([], 1, "", "not found")
    profile = image.removeprefix("ctf-os-sandbox:")
    payload = [{
        "Id": f"sha256:{profile}",
        "Size": 123,
        "Os": "linux",
        "Architecture": "amd64",
        "Config": {"Labels": {
            "org.ctf-os.sandbox": "true",
            "org.ctf-os.profile": profile,
            "org.ctf-os.build-policy": "pre-contest-pinned",
            "org.ctf-os.lock-sha256": expected_lock_sha256(),
            "org.ctf-os.build-sha256": expected_build_sha256(),
        }},
    }]
    return subprocess.CompletedProcess([], 0, json.dumps(payload), "")


def test_all_ten_categories_select_their_recommended_image() -> None:
    assert CATEGORIES == ("base", "pwn", "web", "rev", "crypto", "forensic", "misc", "osint", "ai", "cloud")
    for category in CATEGORIES:
        expected = f"ctf-os-sandbox:{category}"
        runner = lambda argv, expected=expected, **kwargs: _image_result(
            argv[-1], available={expected}
        )
        selected = select_image(category, runner=runner)
        assert recommended_image(category) == expected
        assert selected["selected_image"] == f"sha256:{category}"
        assert selected["status"] == "AVAILABLE"
    with pytest.raises(ValueError):
        canonical_category("mobile")


def test_missing_category_image_degrades_only_to_existing_base_and_otherwise_fails() -> None:
    base_runner = lambda argv, **kwargs: _image_result(argv[-1], available={"ctf-os-sandbox:base"})
    degraded = select_image("pwn", runner=base_runner)
    assert degraded["status"] == "DEGRADED"
    assert degraded["selected_image"] == "sha256:base"
    missing = select_image("pwn", runner=lambda argv, **kwargs: _image_result(argv[-1], available=set()))
    assert missing["status"] == "UNAVAILABLE"
    assert missing["selected_image"] is None
    assert missing["image_available"] is False


def test_image_selection_rejects_wrong_profile_policy_and_platform() -> None:
    def runner(argv, **kwargs):
        payload = [{
            "Id": "sha256:wrong",
            "Size": 1,
            "Os": "windows",
            "Architecture": "amd64",
            "Config": {"Labels": {
                "org.ctf-os.sandbox": "true",
                "org.ctf-os.profile": "pwn",
                "org.ctf-os.build-policy": "unknown",
                "org.ctf-os.lock-sha256": expected_lock_sha256(),
                "org.ctf-os.build-sha256": expected_build_sha256(),
            }},
        }]
        return subprocess.CompletedProcess(argv, 0, json.dumps(payload), "")

    selected = select_image("web", runner=runner)
    assert selected["status"] == "UNAVAILABLE"
    assert selected["image_available"] is False


def test_build_freshness_hash_changes_when_any_sandbox_input_changes(
    tmp_path: Path,
) -> None:
    sandbox = tmp_path / "sandbox"
    (sandbox / "requirements").mkdir(parents=True)
    (sandbox / "Dockerfile.sandbox").write_text("FROM scratch\n", encoding="utf-8")
    requirements = sandbox / "requirements" / "base.txt"
    requirements.write_text("regex==1\n", encoding="utf-8")

    before = images.expected_build_sha256(tmp_path)
    requirements.write_text("regex==2\n", encoding="utf-8")
    after = images.expected_build_sha256(tmp_path)
    requirements.chmod(0o755)
    after_mode_change = images.expected_build_sha256(tmp_path)

    assert before != after
    assert after != after_mode_change


def test_materialization_is_fresh_read_only_and_does_not_modify_incoming(repo: Path) -> None:
    manifest, challenge = write_challenge(repo, files={"src/app.py": b"print(1)\n"})
    source = manifest.path.parent / "web" / "Example" / "src" / "app.py"
    before = source.read_bytes()
    fingerprint = input_fingerprint(manifest, challenge)
    run, _ = create_run(repo, manifest, challenge, input_fingerprint=fingerprint)
    record = prepare_input(manifest, challenge, run, expected_fingerprint=fingerprint)
    prepared, checked = validate_prepared_input(run)
    assert checked == record
    assert prepared != source.parent
    assert (prepared / "src" / "app.py").read_bytes() == before
    assert not ((prepared / "src" / "app.py").stat().st_mode & 0o222)
    assert source.read_bytes() == before
    assert source.stat().st_mode & 0o200


def test_runtime_create_uses_inspected_image_without_pull_and_returns_executable_prefix(tmp_path: Path) -> None:
    source = tmp_path / "input"
    source.mkdir()
    source.chmod(0o555)
    calls: list[list[str]] = []

    def runner(argv, **kwargs):
        calls.append(list(argv))
        if argv[1:2] == ["info"]:
            return subprocess.CompletedProcess(argv, 0, json.dumps({"MemTotal": 32 * 1024**3, "NCPU": 16}), "")
        if argv[1:2] == ["ps"]:
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[1:2] == ["run"]:
            return subprocess.CompletedProcess(argv, 0, "container-id\n", "")
        if argv[1:2] == ["inspect"]:
            return subprocess.CompletedProcess(argv, 0, "true\n", "")
        if argv[1:2] == ["logs"]:
            return subprocess.CompletedProcess(argv, 0, "", "")
        raise AssertionError(argv)

    spec = SandboxSpec(
        run_id="run-123", contest_slug="demo", challenge_id="abc123", category="web",
        lane_id="root", source=source, lane_root=tmp_path / "workers" / "root",
        input_fingerprint="0" * 64, image="ctf-os-sandbox:web",
    )
    metadata = create(spec, runner=runner)
    run_argv = next(argv for argv in calls if argv[1:2] == ["run"])
    assert metadata["status"] == "READY"
    assert metadata["image"] == "ctf-os-sandbox:web"
    assert metadata["exec_command_prefix"][-1] == "--"
    assert "pull" not in run_argv
    assert "ctf-os-sandbox:web" in run_argv


def test_race_prepare_orchestrates_real_root_create_without_manual_command(repo: Path, monkeypatch) -> None:
    _manifest, challenge = write_challenge(repo, files={"app.py": b"print(1)\n"})
    created: list[SandboxSpec] = []

    monkeypatch.setattr(cli, "select_image", lambda category, docker: {
        "status": "AVAILABLE", "recommended_image": "ctf-os-sandbox:web",
        "selected_image": "ctf-os-sandbox:web", "image_available": True,
    })
    monkeypatch.setattr(cli, "prepare_service", lambda *a, **k: {
        "status": "NOT_REQUIRED", "network": None, "endpoints": [], "lifecycle_owner": "root",
    })

    def fake_create(spec, docker="docker"):
        created.append(spec)
        from conftest import fake_sandbox
        return fake_sandbox(spec.lane_root.parents[1], challenge, spec.lane_id, spec.image)

    monkeypatch.setattr(cli, "create", fake_create)
    args = argparse.Namespace(selector="web/Example", contest="Demo CTF", docker="docker", dry_run=False)
    result = cli._race_prepare(repo, args)
    assert result["attack_ready"] is True
    assert result["root_sandbox"]["status"] == "READY"
    assert len(created) == 1 and created[0].lane_id == "root"
    assert "sandbox" + "-create" not in json.dumps(result)
    assert result["next_root_action"]["exec_command_prefix"][-1] == "--"


def test_race_prepare_missing_images_is_explicitly_not_attack_ready(repo: Path, monkeypatch) -> None:
    write_challenge(repo, files={"app.py": b"print(1)\n"})
    monkeypatch.setattr(cli, "select_image", lambda category, docker: {
        "status": "UNAVAILABLE", "recommended_image": "ctf-os-sandbox:web",
        "selected_image": None, "image_available": False, "reason": "no local image",
        "recovery_command": ["sandbox/build-images.sh", "web"],
    })
    args = argparse.Namespace(selector="1", contest="Demo CTF", docker="docker", dry_run=False)
    result = cli._race_prepare(repo, args)
    assert result["attack_ready"] is False
    assert result["root_sandbox"]["status"] == "UNAVAILABLE"
    assert result["next_root_action"]["recovery_command"][-1] == "web"


def test_incomplete_service_cleanup_keeps_recoverable_run_ownership(
    repo: Path, monkeypatch
) -> None:
    write_challenge(repo, files={"app.py": b"print(1)\n"})
    monkeypatch.setattr(cli, "select_image", lambda category, docker: {
        "status": "AVAILABLE", "recommended_image": "ctf-os-sandbox:web",
        "selected_image": "ctf-os-sandbox:web", "image_available": True,
    })
    residual: dict[str, object] = {
        "schema_version": 1,
        "status": "CLEANUP_FAILED",
        "run_id": "pending",
        "challenge_id": "pending",
        "kind": "compose",
        "instance_id": "root",
        "network": "ctf-os-net-residual",
        "endpoints": ["http://challenge:8000"],
        "labels": {"org.ctf-os.managed": "true"},
        "runtime": {
            "compose_files": ["/prepared/compose.yml", "/run/compose.race.yml"],
            "project": "ctf-os-residual",
            "service_count": 1,
        },
        "metadata_path": "/run/service/service.json",
    }

    def failed_prepare(spec, **_kwargs):
        state = dict(residual)
        state.update({
            "run_id": spec.run_id,
            "challenge_id": spec.challenge_id,
            "metadata_path": str(spec.metadata_path),
        })
        raise service_module.ServiceCleanupError(
            "service metadata write failed and cleanup was incomplete: compose down failed",
            service=state,
            failures=["compose down failed"],
        )

    monkeypatch.setattr(cli, "prepare_service", failed_prepare)
    result = cli._race_prepare(
        repo,
        argparse.Namespace(
            selector="web/Example",
            contest="Demo CTF",
            docker="docker",
            dry_run=False,
        ),
    )
    run = resolve_run(repo, result["run_id"])
    persisted = load_race(run)

    assert result["attack_ready"] is False
    assert result["service"]["status"] == "CLEANUP_FAILED"
    assert result["service"]["cleanup_error"] == "compose down failed"
    assert persisted["service_context"]["runtime"]["project"] == "ctf-os-residual"

    cleaned_services: list[dict] = []
    monkeypatch.setattr(
        cli,
        "cleanup_service",
        lambda metadata, **_kwargs: (
            cleaned_services.append(dict(metadata))
            or {"run_id": metadata["run_id"], "cleaned": True, "failures": []}
        ),
    )
    cleanup_result = cli._race_cleanup(
        repo,
        argparse.Namespace(run_id=run.name, docker="docker"),
    )

    assert cleaned_services[0]["runtime"]["project"] == "ctf-os-residual"
    assert cleanup_result["active_cleared"] is True
    with pytest.raises(WorkspaceError):
        resolve_run(repo)
