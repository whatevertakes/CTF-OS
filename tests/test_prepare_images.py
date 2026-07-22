from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess

import pytest

import ctf_os.agent_tools.__main__ as cli
from ctf_os.categories import CATEGORIES, canonical_category
from ctf_os.images import recommended_image, select_image
from ctf_os.preflight import input_fingerprint, prepare_input, validate_prepared_input
from ctf_os.sandbox.runtime import SandboxSpec, build_run_argv, create
from ctf_os.workspace import create_run

from conftest import write_challenge


def _image_result(image: str, *, available: set[str]) -> subprocess.CompletedProcess[str]:
    if image not in available:
        return subprocess.CompletedProcess([], 1, "", "not found")
    payload = [{"Id": f"sha256:{image}", "Size": 123, "Config": {"Labels": {"org.ctf-os.sandbox": "true"}}}]
    return subprocess.CompletedProcess([], 0, json.dumps(payload), "")


def test_all_ten_categories_select_their_recommended_image() -> None:
    assert CATEGORIES == ("base", "pwn", "web", "rev", "crypto", "forensic", "misc", "osint", "ai", "cloud")
    for category in CATEGORIES:
        expected = f"ctf-os-sandbox:{category}"
        runner = lambda argv, **kwargs: _image_result(argv[-1], available={expected})
        selected = select_image(category, runner=runner)
        assert recommended_image(category) == expected
        assert selected["selected_image"] == expected
        assert selected["status"] == "AVAILABLE"
    with pytest.raises(ValueError):
        canonical_category("mobile")


def test_missing_category_image_degrades_only_to_existing_base_and_otherwise_fails() -> None:
    base_runner = lambda argv, **kwargs: _image_result(argv[-1], available={"ctf-os-sandbox:base"})
    degraded = select_image("pwn", runner=base_runner)
    assert degraded["status"] == "DEGRADED"
    assert degraded["selected_image"] == "ctf-os-sandbox:base"
    missing = select_image("pwn", runner=lambda argv, **kwargs: _image_result(argv[-1], available=set()))
    assert missing["status"] == "UNAVAILABLE"
    assert missing["selected_image"] is None
    assert missing["image_available"] is False


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
    manifest, challenge = write_challenge(repo, files={"app.py": b"print(1)\n"})
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
