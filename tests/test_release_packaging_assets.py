"""Packaging-only regressions for release-critical bundled assets."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_bundled_assets_match_the_release_source_assets() -> None:
    """The installed assets must be exact copies of their build inputs."""
    pairs = {
        "config/model-routing.yaml": "ctf_os/resources/model-routing.yaml",
        "sandbox/Dockerfile.sandbox": "ctf_os/resources/sandbox/Dockerfile.sandbox",
        "sandbox/entrypoint.sh": "ctf_os/resources/sandbox/entrypoint.sh",
    }

    for source, bundled in pairs.items():
        assert (ROOT / bundled).read_bytes() == (ROOT / source).read_bytes()


def test_sdist_manifest_declares_release_assets_and_packaging_tests() -> None:
    """Keep sdist rebuild inputs explicit instead of relying on egg-info cache."""
    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
    required_entries = (
        "include config.example.yaml",
        "include config/model-routing.yaml",
        "include sandbox/Dockerfile.sandbox",
        "include sandbox/entrypoint.sh",
        "include sandbox/Dockerfile.profiles",
        "include sandbox/profiles.yaml",
        "graft benchmarks",
        "include scripts/normalize_sdist.py",
        "include scripts/build_team_bundle.sh",
        "recursive-include ctf_os/resources *.yaml Dockerfile.sandbox entrypoint.sh",
        "graft knowledge",
        "graft ctf_os/resources/knowledge",
        "graft docs",
        "graft tests",
    )

    for entry in required_entries:
        assert entry in manifest


def test_bundled_knowledge_seed_matches_source_tree() -> None:
    """Installed knowledge must be exactly the reviewed source seed."""
    source = ROOT / "knowledge"
    bundled = ROOT / "ctf_os" / "resources" / "knowledge"
    source_files = sorted(
        path.relative_to(source) for path in source.rglob("*")
        if path.is_file() and "indexes" not in path.relative_to(source).parts
    )
    bundled_files = sorted(path.relative_to(bundled) for path in bundled.rglob("*") if path.is_file())
    assert bundled_files == source_files
    for relative in source_files:
        assert (bundled / relative).read_bytes() == (source / relative).read_bytes()
