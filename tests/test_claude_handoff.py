from __future__ import annotations

import json
from pathlib import Path

import pytest

from ctf_os.agent_tools.__main__ import main
from ctf_os.claude_handoff import (
    ClaudeHandoffError, MAX_HANDOFF_BYTES, handoff_path, save_handoff,
)
from ctf_os.contest import discover_contests, select_contest
from ctf_os.workspace import challenge_root, start_fresh_attempt

from conftest import write_contest


def _markdown(label: str = "한국어 fact") -> str:
    return f"""# Problem

## Challenge
- Contest: Demo CTF
- Category: misc
- Problem: Problem
- Description: demo
- Flag format: CTF{{...}}
- Remote: example.test:31337

## Confirmed facts
- {label}

## Verified solve history
1. `python probe.py`
   - Observed: returned 1
   - Conclusion: the oracle is reachable

## Refuted paths
- Empty input returned the normal response, refuting the crash path.

## Useful technical material
- framing is 4-byte little endian

## Unresolved state
- exploit payload remains unverified

## Clean start
이 문서는 이전 Codex 풀이에서 실제로 확인된 사실과 실행 기록만 압축한 것이다.
추측이나 정답이 아니므로 원본 문제를 독립적으로 다시 분석하고 최종 flag를 획득하라.
"""


def _source(tmp_path: Path, content: str | None = None) -> Path:
    source = tmp_path / "draft.md"
    source.write_text(content or _markdown(), encoding="utf-8")
    return source


def test_saves_utf8_markdown_at_exact_path(tmp_path: Path) -> None:
    path = save_handoff(
        tmp_path, contest="demo-ctf", challenge="문제-id",
        markdown_file=_source(tmp_path),
    )
    assert path == tmp_path / "rescue" / "demo-ctf" / "문제-id" / "HANDOFF.md"
    assert "한국어 fact" in path.read_text(encoding="utf-8")
    assert list(path.parent.iterdir()) == [path]


def test_rejects_oversize_and_non_utf8_markdown(tmp_path: Path) -> None:
    oversize = tmp_path / "oversize.md"
    oversize.write_bytes(b"x" * (MAX_HANDOFF_BYTES + 1))
    with pytest.raises(ClaudeHandoffError, match="exceeds"):
        save_handoff(tmp_path, contest="c", challenge="p", markdown_file=oversize)
    invalid = tmp_path / "invalid.md"
    invalid.write_bytes(b"\xff")
    with pytest.raises(ClaudeHandoffError, match="UTF-8"):
        save_handoff(tmp_path, contest="c", challenge="p", markdown_file=invalid)


def test_rejects_symlink_input(tmp_path: Path) -> None:
    source = _source(tmp_path)
    link = tmp_path / "link.md"
    link.symlink_to(source)
    with pytest.raises(ClaudeHandoffError, match="non-symlink"):
        save_handoff(tmp_path, contest="c", challenge="p", markdown_file=link)


@pytest.mark.parametrize("component", ("..", "../escape", "a/../b"))
def test_rejects_path_traversal(tmp_path: Path, component: str) -> None:
    with pytest.raises(ClaudeHandoffError, match="unsafe"):
        handoff_path(tmp_path, contest=component, challenge="p")


def test_replaces_separators_but_preserves_safe_unicode(tmp_path: Path) -> None:
    path = handoff_path(tmp_path, contest="대회/2026", challenge="문제\0name")
    assert path.relative_to(tmp_path).parts == (
        "rescue", "대회-2026", "문제-name", "HANDOFF.md",
    )


def test_rejects_symlink_output_directory(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "rescue").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ClaudeHandoffError, match="symlink"):
        save_handoff(tmp_path, contest="c", challenge="p", markdown_file=_source(tmp_path))
    assert not any(outside.iterdir())


def test_atomic_replace_leaves_one_latest_handoff(tmp_path: Path) -> None:
    source = _source(tmp_path, _markdown("first"))
    path = save_handoff(tmp_path, contest="c", challenge="p", markdown_file=source)
    first_inode = path.stat().st_ino
    source.write_text(_markdown("second"), encoding="utf-8")
    replaced = save_handoff(tmp_path, contest="c", challenge="p", markdown_file=source)
    assert replaced == path
    assert "second" in path.read_text(encoding="utf-8")
    assert path.stat().st_ino != first_inode
    assert [item.name for item in path.parent.iterdir()] == ["HANDOFF.md"]


def test_different_challenge_is_not_modified(tmp_path: Path) -> None:
    source = _source(tmp_path, _markdown("one"))
    first = save_handoff(tmp_path, contest="c", challenge="one", markdown_file=source)
    before = first.read_bytes()
    source.write_text(_markdown("two"), encoding="utf-8")
    second = save_handoff(tmp_path, contest="c", challenge="two", markdown_file=source)
    assert first.read_bytes() == before
    assert second != first


def test_cli_requires_current_exact_run_and_saves_by_manifest_identity(repo: Path) -> None:
    write_contest(repo, """# Demo CTF
- flag format: CTF{...}

### misc/Problem
- description: demo
- remote: example.test:31337
""")
    manifest = select_contest(discover_contests(repo / "incoming"), "Demo CTF")
    challenge = manifest.challenges[0]
    workspace = challenge_root(repo, manifest, challenge)
    (workspace / "input").mkdir(parents=True)
    (workspace / "input" / "task.txt").write_text("input", encoding="utf-8")
    current = start_fresh_attempt(workspace, challenge, "fingerprint")
    old = start_fresh_attempt(workspace, challenge, "fingerprint")
    current = start_fresh_attempt(workspace, challenge, "fingerprint")
    draft = _source(repo)

    assert main([
        "--repo", str(repo), "claude-handoff-save", "1",
        "--contest", "Demo CTF", "--run-id", old.name,
        "--markdown-file", str(draft),
    ]) == 2
    assert main([
        "--repo", str(repo), "claude-handoff-save", "1",
        "--contest", "Demo CTF", "--run-id", current.name,
        "--markdown-file", str(draft),
    ]) == 0
    destination = repo / "rescue" / manifest.slug / challenge.id / "HANDOFF.md"
    assert destination.read_text(encoding="utf-8") == draft.read_text(encoding="utf-8")


def test_skill_contract_covers_evidence_content_and_terminal_user_flow() -> None:
    skill = Path(".codex/skills/ctf-claude-handoff/SKILL.md").read_text(encoding="utf-8")
    for required in (
        "클로드 구조대 준비해라", "RUN_MANIFEST.json", "SESSION-INPUT.json",
        "## Confirmed facts", "## Verified solve history", "## Refuted paths",
        "## Useful technical material", "## Unresolved state", "## Clean start",
        "at most ten", "at most 100 lines", "32 KiB", "PRIMITIVE_CONFIRMED",
        "Do not ask", "Stop all new recon", "claude-handoff-save",
        "원본 문제 ZIP과 이 파일을 사용자가 직접 Claude 시스템으로 옮기면 됩니다.",
        "이 문제에 대한 Codex 풀이를 여기서 종료합니다.",
    ):
        assert required in skill
    for forbidden in (
        "rescue-" + "return-validate", "rescue-" + "flag-promote",
        "Start command", "packet digest", "rescue ID",
    ):
        assert forbidden not in skill


def test_legacy_bridge_and_rescue_cli_are_absent() -> None:
    assert not Path("ctf_os", "claude_" + "bridge.py").exists()
    assert not Path("tests", "test_claude_" + "bridge.py").exists()
    assert not Path(".codex/skills/ctf-claude-rescue-prepare").exists()
    assert not Path(".codex/skills/ctf-claude-resume").exists()
    source = Path("ctf_os/agent_tools/__main__.py").read_text(encoding="utf-8")
    for command in (
        "rescue-prepare", "rescue-show", "rescue-" + "runtime-record",
        "rescue-" + "return-validate", "rescue-close", "rescue-" + "flag-promote",
    ):
        assert command not in source
