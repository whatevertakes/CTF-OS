from __future__ import annotations

from pathlib import Path
import subprocess
import tarfile


ROOT = Path(__file__).parents[1]


def test_team_bundle_is_reproducible_and_excludes_local_runtime_data(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    script = ROOT / "scripts" / "build_team_bundle.sh"
    (repo / "scripts" / script.name).write_bytes(script.read_bytes())
    (repo / "scripts" / "deploy_ctf_os.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    (repo / "README.md").write_text("# Demo\n", encoding="utf-8")
    (repo / "config.example.yaml").write_text("mode: local_node\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "fixture"], cwd=repo, check=True)

    command = ["bash", str(repo / "scripts" / script.name), "--output-dir", str(repo / "dist")]
    subprocess.run(command, cwd=repo, check=True, text=True, capture_output=True)
    archive = next((repo / "dist").glob("*.tar.gz"))
    first = archive.read_bytes()
    subprocess.run(command, cwd=repo, check=True, text=True, capture_output=True)

    assert archive.read_bytes() == first
    assert archive.with_suffix(archive.suffix + ".sha256").is_file()
    with tarfile.open(archive, "r:gz") as bundle:
        names = set(bundle.getnames())
    assert {"CTF-OS/README.md", "CTF-OS/config.example.yaml"} <= names
    assert not any("local." in name or name.endswith((".db", ".pem", ".key")) for name in names)


def test_team_bundle_refuses_uncommitted_tracked_changes(tmp_path: Path) -> None:
    script = (ROOT / "scripts" / "build_team_bundle.sh").read_text(encoding="utf-8")
    assert "git status --porcelain --untracked-files=no" in script
    assert "commit them before building a team bundle" in script
    assert "benchmarks/results/" in script
