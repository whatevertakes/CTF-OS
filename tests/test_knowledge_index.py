from __future__ import annotations

import json
from pathlib import Path

import pytest

from ctf_os.cli import main
from ctf_os.solver_engine.knowledge import KnowledgeChunk, KnowledgeIndex


def test_source_seed_covers_all_categories_and_core_tool_cheatsheets() -> None:
    root = Path(__file__).parents[1] / "knowledge"
    categories = {"pwn", "web", "rev", "crypto", "forensics", "misc", "cloud"}
    expected_tools = {
        "pwntools", "gdb", "radare2", "angr", "z3", "rsa_ctf_tool", "binwalk", "steghide", "zsteg", "curl", "tshark", "ffmpeg",
    }
    assert {path.stem for path in (root / "playbooks").glob("*.md")} == categories
    assert {path.stem for path in (root / "tools").glob("*.md")} == expected_tools
    for category in categories:
        text = (root / "playbooks" / f"{category}.md").read_text(encoding="utf-8").casefold()
        assert all(marker in text for marker in ("recon", "hypotheses", "tool", "validation", "replay"))


def _seed(root: Path) -> None:
    (root / "playbooks").mkdir(parents=True)
    (root / "tools").mkdir()
    (root / "writeups" / "web").mkdir(parents=True)
    (root / "playbooks" / "web.md").write_text(
        "# Web\n\n## Template errors\n\nInvestigate server-side template injection with a local baseline.\n"
        "\n## Authorization\n\nCompare authorization boundaries and request ownership.\n",
        encoding="utf-8",
    )
    (root / "playbooks" / "pwn.md").write_text(
        "# Pwn\n\n## Protections\n\nUse checksec and validate local offsets before replay.\n", encoding="utf-8"
    )
    (root / "tools" / "curl.md").write_text(
        "# curl\n\nUse curl only for an explicitly authorized challenge URL.\n", encoding="utf-8"
    )
    (root / "writeups" / "web" / "notes.md").write_text(
        "# Notes\n\nA reflected template expression can guide an SSTI hypothesis.\n", encoding="utf-8"
    )


def test_refresh_is_persistent_deterministic_and_ignores_unsafe_generated_content(tmp_path: Path) -> None:
    root = tmp_path / "knowledge"
    _seed(root)
    (root / "indexes").mkdir()
    (root / "indexes" / "ignored.md").write_text("self ingestion must not happen", encoding="utf-8")
    (root / "binary.md").write_bytes(b"safe-looking\x00binary")
    (root / "large.md").write_text("x" * 256_001, encoding="utf-8")
    outside = tmp_path / "outside.md"
    outside.write_text("outside content", encoding="utf-8")
    link = root / "linked.md"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable on this filesystem")

    first = KnowledgeIndex.refresh(root)
    first_jsonl = first.chunks_file.read_bytes()
    second = KnowledgeIndex.refresh(root)

    assert first.chunk_count == second.chunk_count
    assert first_jsonl == second.chunks_file.read_bytes()
    assert {"binary.md", "large.md", "linked.md"}.issubset(set(first.skipped_files))
    rows = [json.loads(line) for line in first.chunks_file.read_text(encoding="utf-8").splitlines()]
    assert all("indexes/" not in row["source"] for row in rows)
    assert rows == sorted(rows, key=lambda row: row["id"])
    index = KnowledgeIndex.open_root(root)
    try:
        assert index.retrieve("self ingestion", category="web") == []
        assert index.retrieve("template", category="web")[0].category == "web"
    finally:
        index.close()


def test_structured_retrieval_weights_findings_and_is_deterministic() -> None:
    index = KnowledgeIndex()
    try:
        index.index(
            [
                KnowledgeChunk("a-general", "knowledge/playbooks/web.md", "web", "Generic login and request notes."),
                KnowledgeChunk("z-ssti", "knowledge/writeups/web/x.md", "web", "Template expression reflected; validate SSTI safely.", ("ssti",)),
                KnowledgeChunk("tool-curl", "knowledge/tools/curl.md", "tools", "curl captures authorized request baselines.", (), ("curl",)),
            ]
        )
        results = index.query(category="web", challenge_name="login", findings=("template expression reflected",), limit=3)
        assert [item.id for item in results] == ["z-ssti", "a-general"]
        assert index.retrieve("curl", category="web")[0].id == "tool-curl"
    finally:
        index.close()


def test_cli_knowledge_index_and_prompt_ready_query_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = tmp_path / "knowledge"
    _seed(root)
    assert main(["knowledge", "index", "--root", str(root)]) == 0
    assert (root / "indexes" / "knowledge.sqlite").is_file()
    assert main([
        "knowledge", "query", "--root", str(root), "--category", "web", "--text", "template",
        "--finding", "template expression reflected", "--limit", "2",
    ]) == 0
    output = capsys.readouterr().out
    assert "[knowledge id=" in output
    assert "source=knowledge/playbooks/web.md" in output or "source=knowledge/writeups/web/notes.md" in output
    assert "tags:" in output and "tools:" in output


def test_cli_materializes_bundled_seed_when_default_root_is_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(["knowledge", "index"]) == 0
    assert (tmp_path / "knowledge" / "playbooks" / "cloud.md").is_file()
    assert (tmp_path / "knowledge" / "indexes" / "knowledge.sqlite").is_file()
