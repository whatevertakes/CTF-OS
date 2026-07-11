from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess

import pytest

from ctf_os.cli import main
from ctf_os.solver_engine.knowledge import KnowledgeChunk, KnowledgeIndex
from ctf_os.solver_engine.knowledge_import import (
    PINNED_COMMIT,
    KnowledgeImportError,
    audit_snapshot,
    import_snapshot,
)


ROOT = Path(__file__).parents[1]


def _source(tmp_path: Path) -> Path:
    """Materialize a local checkout whose content exactly matches the pin."""
    source = tmp_path / "ctf-skills"
    shutil.copytree(ROOT / "knowledge" / "external" / "ctf-skills", source)
    # The importer reads this local Git metadata descriptor-safely; no git
    # executable is invoked by the test or implementation.
    ref = source / ".git" / "refs" / "heads"
    ref.mkdir(parents=True)
    (source / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="ascii")
    (ref / "main").write_text(f"{PINNED_COMMIT}\n", encoding="ascii")
    return source


def _snapshot_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_import_is_local_deterministic_and_records_section_trust(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = _source(tmp_path)
    destination = tmp_path / "knowledge" / "external" / "ctf-skills"
    def blocked(*_args, **_kwargs):
        raise AssertionError("knowledge import must not execute subprocesses or use the network")

    monkeypatch.setattr(subprocess, "run", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    first = import_snapshot(source, destination, commit=PINNED_COMMIT)
    first_bytes = _snapshot_bytes(destination)
    (destination / "stale.md").write_text("must disappear", encoding="utf-8")
    second = import_snapshot(source, destination, commit=PINNED_COMMIT)

    assert (first.file_count, first.total_bytes) == (98, 2_129_326)
    assert second == first
    assert _snapshot_bytes(destination) == first_bytes
    assert not (destination / "stale.md").exists()
    audit = audit_snapshot(destination)
    assert audit.valid and audit.trust_counts["accepted"] and audit.trust_counts["reviewed"] and audit.trust_counts["quarantined"]
    manifest = json.loads((destination / "manifest.json").read_text(encoding="utf-8"))
    entry = manifest["files"][0]
    assert entry["original_path"] == "ctf-crypto/advanced-math.md"
    assert entry["sha256"] == hashlib.sha256((source / entry["original_path"]).read_bytes()).hexdigest()
    assert {section["classification"] for file_entry in manifest["files"] for section in file_entry["sections"]} >= {
        "accepted", "reviewed", "quarantined",
    }
    assert (destination / "LICENSE").read_bytes() == (source / "LICENSE").read_bytes()
    assert "Lukasz Jagiello" in (destination / "NOTICE.md").read_text(encoding="utf-8")


def test_imported_trust_is_excluded_by_default_and_preserved_in_index_metadata(tmp_path: Path) -> None:
    source = _source(tmp_path)
    root = tmp_path / "knowledge"
    import_snapshot(source, root / "external" / "ctf-skills", commit=PINNED_COMMIT, families=("web",))
    refreshed = KnowledgeIndex.refresh(root)
    rows = [json.loads(line) for line in refreshed.chunks_file.read_text(encoding="utf-8").splitlines()]
    assert any(row["trust"] == "quarantined" and "prompt-control" in row["flags"] for row in rows)
    assert any(row["trust"] == "reviewed" and row["provenance"]["commit"] == PINNED_COMMIT for row in rows)
    index = KnowledgeIndex.open_root(root)
    try:
        assert index.retrieve("", category="web")
        assert {chunk.trust for chunk in index.retrieve("", category="web")} == {"accepted"}
        assert index.retrieve("", category="web", trust="reviewed")
        assert {chunk.trust for chunk in index.retrieve("", category="web", trust="reviewed")} == {"reviewed"}
        assert index.retrieve("", category="web", trust="quarantined")
    finally:
        index.close()


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (b"# Broken\x00\n", "NUL byte blocked"),
        (b"# Broken\xff\n", "invalid UTF-8 blocked"),
        ("# Large\n" + "x" * 256_001, "oversized file blocked"),
    ],
)
def test_import_blocks_unsafe_markdown_without_touching_destination(tmp_path: Path, content: str | bytes, expected: str) -> None:
    source = _source(tmp_path)
    target = source / "ctf-web" / "auth-and-access.md"
    if isinstance(content, bytes):
        target.write_bytes(content)
    else:
        target.write_text(content, encoding="utf-8")
    destination = tmp_path / "knowledge" / "external" / "ctf-skills"
    destination.mkdir(parents=True)
    sentinel = destination / "sentinel"
    sentinel.write_text("unchanged", encoding="utf-8")
    with pytest.raises(KnowledgeImportError, match=expected):
        import_snapshot(source, destination, commit=PINNED_COMMIT, families=("web",))
    assert sentinel.read_text(encoding="utf-8") == "unchanged"


def test_import_blocks_symlinks_and_wrong_checkout_commit(tmp_path: Path) -> None:
    source = _source(tmp_path)
    outside = tmp_path / "outside.md"
    outside.write_text("# outside", encoding="utf-8")
    try:
        (source / "ctf-web" / "linked.md").symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable on this filesystem")
    with pytest.raises(KnowledgeImportError, match="symlink blocked"):
        import_snapshot(source, tmp_path / "knowledge" / "external" / "ctf-skills", commit=PINNED_COMMIT, families=("web",))
    (source / "ctf-web" / "linked.md").unlink()
    (source / ".git" / "refs" / "heads" / "main").write_text("f" * 40 + "\n", encoding="ascii")
    with pytest.raises(KnowledgeImportError, match="source checkout"):
        import_snapshot(source, tmp_path / "other" / "ctf-skills", commit=PINNED_COMMIT, families=("web",))


def test_import_rejects_dirty_checkout_with_a_pinned_head(tmp_path: Path) -> None:
    source = _source(tmp_path)
    dirty = source / "ctf-web" / "sql-injection.md"
    dirty.write_text(dirty.read_text(encoding="utf-8") + "\n<!-- dirty checkout -->\n", encoding="utf-8")

    # HEAD remains the pin, so this proves that HEAD-only provenance is not
    # sufficient to pass the import boundary.
    assert (source / ".git" / "refs" / "heads" / "main").read_text(encoding="ascii").strip() == PINNED_COMMIT
    with pytest.raises(KnowledgeImportError, match="canonical pinned snapshot"):
        import_snapshot(source, tmp_path / "knowledge" / "external" / "ctf-skills", commit=PINNED_COMMIT, families=("web",))


def test_import_rejects_optional_families_without_canonical_hashes(tmp_path: Path) -> None:
    with pytest.raises(KnowledgeImportError, match="optional knowledge families"):
        import_snapshot(
            _source(tmp_path), tmp_path / "knowledge" / "external" / "ctf-skills",
            commit=PINNED_COMMIT, families=("osint",),
        )


def test_extra_external_file_invalidates_audit_and_is_never_retrieved(tmp_path: Path) -> None:
    source = _source(tmp_path)
    root = tmp_path / "knowledge"
    snapshot = root / "external" / "ctf-skills"
    import_snapshot(source, snapshot, commit=PINNED_COMMIT, families=("web",))
    rogue = snapshot / "ctf-web" / "rogue.md"
    rogue.write_text("# Rogue\n\nrogue-marker must never reach RAG.\n", encoding="utf-8")

    audit = audit_snapshot(snapshot)
    assert not audit.valid
    assert any("unregistered snapshot file: ctf-web/rogue.md" in error for error in audit.errors)
    refreshed = KnowledgeIndex.refresh(root)
    assert refreshed.chunk_count == 0
    assert "external/ctf-skills/ctf-web/rogue.md" in refreshed.skipped_files
    index = KnowledgeIndex.open_root(root)
    try:
        assert index.retrieve("rogue-marker", category="web") == []
    finally:
        index.close()


def test_invalid_external_manifest_quarantines_the_entire_subtree(tmp_path: Path) -> None:
    source = _source(tmp_path)
    root = tmp_path / "knowledge"
    snapshot = root / "external" / "ctf-skills"
    import_snapshot(source, snapshot, commit=PINNED_COMMIT, families=("web",))
    manifest_path = snapshot / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"] = []
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    assert not audit_snapshot(snapshot).valid
    refreshed = KnowledgeIndex.refresh(root)
    assert refreshed.chunk_count == 0
    assert any(path.startswith("external/ctf-skills/ctf-web/") for path in refreshed.skipped_files)


def test_audit_rejects_snapshot_symlinks(tmp_path: Path) -> None:
    source = _source(tmp_path)
    snapshot = tmp_path / "knowledge" / "external" / "ctf-skills"
    import_snapshot(source, snapshot, commit=PINNED_COMMIT, families=("web",))
    try:
        (snapshot / "ctf-web" / "linked.md").symlink_to(snapshot / "ctf-web" / "sql-injection.md")
    except OSError:
        pytest.skip("symlinks unavailable on this filesystem")
    audit = audit_snapshot(snapshot)
    assert not audit.valid
    assert any("symlink blocked in snapshot: ctf-web/linked.md" in error for error in audit.errors)


def test_cli_import_dry_run_and_query_trust_controls(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source = _source(tmp_path)
    root = tmp_path / "knowledge"
    assert main([
        "knowledge", "import", str(source), "--root", str(root), "--commit", PINNED_COMMIT,
        "--family", "web", "--dry-run", "--json",
    ]) == 0
    assert json.loads(capsys.readouterr().out)["dry_run"] is True
    assert not (root / "external").exists()
    import_snapshot(source, root / "external" / "ctf-skills", commit=PINNED_COMMIT, families=("web",))
    KnowledgeIndex.refresh(root)
    assert main(["knowledge", "query", "--root", str(root), "--category", "web", "--text", "", "--json"]) == 0
    assert {row["trust"] for row in json.loads(capsys.readouterr().out)} == {"accepted"}
    assert main([
        "knowledge", "query", "--root", str(root), "--category", "web", "--text", "",
        "--trust", "reviewed", "--json",
    ]) == 0
    assert json.loads(capsys.readouterr().out)[0]["trust"] == "reviewed"


def test_metadata_migrates_legacy_index_and_marks_truncated_chunks(tmp_path: Path) -> None:
    database = tmp_path / "legacy.sqlite"
    connection = sqlite3.connect(database)
    connection.execute(
        "CREATE TABLE knowledge_chunks (id TEXT PRIMARY KEY, source TEXT NOT NULL, category TEXT NOT NULL, "
        "content TEXT NOT NULL, tags TEXT NOT NULL, tools TEXT NOT NULL)"
    )
    connection.commit()
    connection.close()
    index = KnowledgeIndex(database)
    try:
        index.index([KnowledgeChunk("reviewed", "x.md", "web", "metadata", trust="reviewed", flags=("credential",))])
        assert index.retrieve("metadata", category="web") == []
        assert index.retrieve("metadata", category="web", trust="reviewed")[0].flags == ("credential",)
        columns = {row["name"] for row in index.connection.execute("PRAGMA table_info(knowledge_chunks)")}
        assert {"trust", "provenance", "flags", "truncated", "links"} <= columns
    finally:
        index.close()

    root = tmp_path / "knowledge"
    root.mkdir()
    (root / "long.md").write_text("# Long\n\n" + "x" * 8_001, encoding="utf-8")
    result = KnowledgeIndex.refresh(root)
    row = json.loads(result.chunks_file.read_text(encoding="utf-8").splitlines()[0])
    assert row["truncated"] is True and len(row["content"]) == 8_000


def test_pinned_packaged_snapshot_has_exact_count_size_sha_and_source_resource_parity() -> None:
    source = ROOT / "knowledge" / "external" / "ctf-skills"
    bundled = ROOT / "ctf_os" / "resources" / "knowledge" / "external" / "ctf-skills"
    assert audit_snapshot(source).valid
    manifest = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["upstream"]["commit"] == PINNED_COMMIT
    assert (manifest["file_count"], manifest["total_bytes"]) == (98, 2_129_326)
    assert all(
        hashlib.sha256((source / entry["original_path"]).read_bytes()).hexdigest() == entry["sha256"]
        for entry in manifest["files"]
    )
    assert _snapshot_bytes(bundled) == _snapshot_bytes(source)
