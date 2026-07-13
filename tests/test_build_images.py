from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
BUILD_SCRIPT = ROOT / "sandbox" / "build-images.sh"


def _fake_docker(tmp_path: Path) -> tuple[Path, Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "docker.jsonl"
    docker = bin_dir / "docker"
    docker.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "config = Path(os.environ['DOCKER_CONFIG'])\n"
        "entry = {\n"
        "    'args': sys.argv[1:],\n"
        "    'docker_config': str(config),\n"
        "    'config': json.loads((config / 'config.json').read_text()),\n"
        "}\n"
        "with Path(os.environ['DOCKER_TEST_LOG']).open('a') as stream:\n"
        "    stream.write(json.dumps(entry) + '\\n')\n",
        encoding="utf-8",
    )
    docker.chmod(0o755)
    return bin_dir, log


def _run_build(tmp_path: Path, docker_config: Path | None = None) -> list[dict[str, object]]:
    bin_dir, log = _fake_docker(tmp_path)
    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    env["DOCKER_TEST_LOG"] = str(log)
    env["TMPDIR"] = str(tmp_path)
    if docker_config is None:
        env.pop("DOCKER_CONFIG", None)
    else:
        env["DOCKER_CONFIG"] = str(docker_config)

    subprocess.run([str(BUILD_SCRIPT)], cwd=ROOT, env=env, check=True, capture_output=True, text=True)
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


def test_build_images_uses_temporary_empty_docker_config(tmp_path: Path) -> None:
    entries = _run_build(tmp_path)

    assert len(entries) == 6
    configs = {str(entry["docker_config"]) for entry in entries}
    assert len(configs) == 1
    assert all(entry["config"] == {"auths": {}} for entry in entries)
    assert not Path(configs.pop()).exists()


def test_build_images_respects_explicit_docker_config(tmp_path: Path) -> None:
    docker_config = tmp_path / "custom-docker"
    docker_config.mkdir()
    expected = {"auths": {}, "currentContext": "test-context"}
    (docker_config / "config.json").write_text(json.dumps(expected), encoding="utf-8")

    entries = _run_build(tmp_path, docker_config)

    assert len(entries) == 6
    assert all(entry["docker_config"] == str(docker_config) for entry in entries)
    assert all(entry["config"] == expected for entry in entries)
