from pathlib import Path

import pytest

from ctf_os.contest import parse_contest
from ctf_os.intake import run_intake
from ctf_os.problems import ProblemsError, parse_problems, sync_contest_manifest


def _write_problems(repo: Path, text: str, name: str = "Demo CTF") -> Path:
    root = repo / "incoming" / name
    root.mkdir(parents=True, exist_ok=True)
    path = root / "problems.txt"
    path.write_text(text, encoding="utf-8")
    return path


def test_problems_intake_generates_manifest_and_preserves_multiple_remotes(repo: Path) -> None:
    _write_problems(repo, """대회명: Demo CTF
플래그 형식: DEMO{...}

pwn/Good
설명: binary
원격: nc one.example 31337
원격: nc two.example 31338
""")
    source = repo / "incoming" / "Demo CTF" / "pwn" / "Good"
    source.mkdir(parents=True)
    (source / "challenge").write_text("data", encoding="utf-8")

    result = run_intake(repo)

    manifest = parse_contest(repo / "incoming" / "Demo CTF" / "contest.md")
    assert [challenge.key for challenge in manifest.challenges] == ["pwn/Good"]
    assert manifest.challenges[0].remotes == ("nc one.example 31337", "nc two.example 31338")
    assert "플래그 패턴:" not in (repo / "incoming" / "Demo CTF" / "contest.md").read_text(encoding="utf-8")
    assert result["challenges"][0]["status"] == "READY"


def test_problems_update_replaces_the_generated_manifest_without_duplicates(repo: Path) -> None:
    path = _write_problems(repo, """misc/Toy
설명: first
""")
    source = repo / "incoming" / "Demo CTF" / "misc" / "Toy"
    source.mkdir(parents=True)
    (source / "value").write_text("x", encoding="utf-8")
    run_intake(repo)

    path.write_text("""misc/Toy
설명: updated
""", encoding="utf-8")
    run_intake(repo)

    manifest = parse_contest(repo / "incoming" / "Demo CTF" / "contest.md")
    assert len(manifest.challenges) == 1
    assert manifest.challenges[0].description == "updated"


def test_problems_duplicate_entries_are_rejected_before_manifest_update(repo: Path) -> None:
    path = _write_problems(repo, """pwn/Same

pwn/Same
""")

    with pytest.raises(ProblemsError, match="duplicate"):
        parse_problems(path)


def test_existing_manifest_still_runs_without_problems_txt(repo: Path) -> None:
    root = repo / "incoming" / "Legacy"
    root.mkdir()
    manifest_path = root / "contest.md"
    manifest_path.write_text("# Legacy\n### misc/Toy\n", encoding="utf-8")
    source = root / "misc" / "Toy"
    source.mkdir(parents=True)
    (source / "value").write_text("x", encoding="utf-8")

    result = run_intake(repo, "Legacy")

    assert result["contest"]["name"] == "Legacy"
    assert manifest_path.read_text(encoding="utf-8") == "# Legacy\n### misc/Toy\n"


def test_sync_creates_manifest_when_only_problems_txt_exists(repo: Path) -> None:
    _write_problems(repo, "web/App\n원격: https://example.test\n")

    manifest_path = sync_contest_manifest(repo, "Demo CTF")

    assert manifest_path == repo / "incoming" / "Demo CTF" / "contest.md"
    assert parse_contest(manifest_path).challenges[0].key == "web/App"


def test_problems_preserve_aliases_profiles_and_flag_configuration(repo: Path) -> None:
    _write_problems(repo, r"""플래그 형식: DEMO{...}
플래그 패턴: \ADEMO\{[a-z]+\}\Z
입력 프로필: large

forensics/Disk
입력 프로필: large-forensic
""")

    manifest_path = sync_contest_manifest(repo, "Demo CTF")
    manifest = parse_contest(manifest_path)

    assert manifest.flag_format == "DEMO{...}"
    assert manifest.flag_pattern == r"\ADEMO\{[a-z]+\}\Z"
    assert manifest.input_profile == "large"
    assert manifest.challenges[0].category == "forensic"
    assert manifest.challenges[0].input_profile == "large-forensic"
