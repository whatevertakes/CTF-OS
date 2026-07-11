from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_team_deployment_script_preserves_runtime_data_and_does_not_auto_run() -> None:
    script = (ROOT / "scripts" / "deploy_ctf_os.sh").read_text(encoding="utf-8")
    assert "uv sync --frozen" in script
    assert "ctf-os state migrate" in script
    assert "docker image inspect" in script
    assert "docker build -f sandbox/Dockerfile.sandbox" in script
    assert "verify_sandbox_image.sh" in script
    assert "ctf-os run" not in script
    for destructive in ("rm -rf incoming", "rm -rf output", "rm -rf sync", "git clean", "git reset"):
        assert destructive not in script


def test_team_deployment_document_keeps_image_build_explicit() -> None:
    document = (ROOT / "docs" / "CTF_OS_TEAM_DEPLOYMENT.md").read_text(encoding="utf-8")
    assert "ctf-os run` never builds the image automatically" in document
    assert "17179869184" not in document or "16 GiB" in document
