"""Local, deterministic CTF knowledge indexing and retrieval.

The index deliberately reads only files below a caller-provided knowledge root.
It never follows symlinks and does not perform any network access.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass, field
from hashlib import sha256
from importlib import resources
from pathlib import Path
from typing import Iterable, Iterator, Mapping, Sequence

from .knowledge_import import audit_snapshot, classify_markdown_sections


_CATEGORIES = frozenset({"pwn", "web", "rev", "crypto", "forensics", "misc", "cloud"})
_INDEX_DIRECTORY = "indexes"
_DATABASE_NAME = "knowledge.sqlite"
_CHUNKS_NAME = "chunks.jsonl"
_MAX_FILE_BYTES = 256_000
_MAX_CHUNK_CHARS = 8_000
_WORD_RE = re.compile(r"[\w-]+", re.UNICODE)
_URL_RE = re.compile(r"https?://[^\s)\]>\"']+", re.IGNORECASE)
_TRUST_VALUES = frozenset({"accepted", "reviewed", "quarantined", "skipped"})
_TOOL_ALLOWLIST = (
    "angr", "binwalk", "burp", "checksec", "curl", "exiftool", "ffmpeg", "foremost", "gdb", "gef",
    "ghidra", "hashcat", "ida", "john", "ltrace", "masscan", "nmap", "objdump", "peda", "pwntools",
    "radare2", "readelf", "rizin", "sqlmap", "strace", "strings", "tshark", "volatility", "wireshark",
    "z3", "zsteg", "steghide", "rsa_ctf_tool",
)


@dataclass(frozen=True)
class KnowledgeChunk:
    id: str
    source: str
    category: str
    content: str
    tags: tuple[str, ...] = ()
    tools: tuple[str, ...] = ()
    trust: str = "accepted"
    provenance: Mapping[str, object] = field(default_factory=dict)
    flags: tuple[str, ...] = ()
    truncated: bool = False
    links: tuple[str, ...] = ()


@dataclass(frozen=True)
class IndexRefreshResult:
    """Stable summary of a local index refresh."""

    root: Path
    database: Path
    chunks_file: Path
    chunk_count: int
    skipped_files: tuple[str, ...] = ()


class KnowledgeIndex:
    """SQLite FTS5-first knowledge store with deterministic fallback ranking."""

    def __init__(self, database: str | Path = ":memory:") -> None:
        self.database = Path(database) if str(database) != ":memory:" else None
        self.connection = sqlite3.connect(str(database))
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS knowledge_chunks ("
            "id TEXT PRIMARY KEY, source TEXT NOT NULL, category TEXT NOT NULL, "
            "content TEXT NOT NULL, tags TEXT NOT NULL, tools TEXT NOT NULL, "
            "trust TEXT NOT NULL DEFAULT 'accepted', provenance TEXT NOT NULL DEFAULT '{}', "
            "flags TEXT NOT NULL DEFAULT '[]', truncated INTEGER NOT NULL DEFAULT 0, "
            "links TEXT NOT NULL DEFAULT '[]')"
        )
        self._migrate_metadata_columns()
        self.fts_available = self._create_fts_table()

    def _migrate_metadata_columns(self) -> None:
        """Additive migration for indexes produced before trust metadata existed."""
        existing = {row["name"] for row in self.connection.execute("PRAGMA table_info(knowledge_chunks)")}
        additions = {
            "trust": "TEXT NOT NULL DEFAULT 'accepted'",
            "provenance": "TEXT NOT NULL DEFAULT '{}'",
            "flags": "TEXT NOT NULL DEFAULT '[]'",
            "truncated": "INTEGER NOT NULL DEFAULT 0",
            "links": "TEXT NOT NULL DEFAULT '[]'",
        }
        with self.connection:
            for name, definition in additions.items():
                if name not in existing:
                    self.connection.execute(f"ALTER TABLE knowledge_chunks ADD COLUMN {name} {definition}")

    def _create_fts_table(self) -> bool:
        try:
            self.connection.execute(
                "CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts "
                "USING fts5(id UNINDEXED, category UNINDEXED, text)"
            )
        except sqlite3.OperationalError:
            return False
        return True

    def close(self) -> None:
        self.connection.close()

    def index(self, chunks: Iterable[KnowledgeChunk]) -> None:
        """Upsert chunks while preserving the small API used by the application."""
        rows = sorted(chunks, key=lambda chunk: chunk.id)
        with self.connection:
            for chunk in rows:
                if chunk.trust not in _TRUST_VALUES:
                    raise ValueError(f"unknown knowledge trust value: {chunk.trust}")
                tags = " ".join(chunk.tags)
                tools = " ".join(chunk.tools)
                self.connection.execute(
                    "INSERT OR REPLACE INTO knowledge_chunks("
                    "id, source, category, content, tags, tools, trust, provenance, flags, truncated, links) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        chunk.id, chunk.source, chunk.category.lower(), chunk.content, tags, tools, chunk.trust,
                        json.dumps(dict(chunk.provenance), ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                        json.dumps(list(chunk.flags), ensure_ascii=False, separators=(",", ":")), int(chunk.truncated),
                        json.dumps(list(chunk.links), ensure_ascii=False, separators=(",", ":")),
                    ),
                )
                if self.fts_available:
                    self.connection.execute("DELETE FROM knowledge_fts WHERE id = ?", (chunk.id,))
                    self.connection.execute(
                        "INSERT INTO knowledge_fts(id, category, text) VALUES (?, ?, ?)",
                        (chunk.id, chunk.category.lower(), " ".join((chunk.content, tags, tools))),
                    )

    def replace(self, chunks: Iterable[KnowledgeChunk]) -> None:
        """Replace the complete store; used only by deterministic refreshes."""
        with self.connection:
            self.connection.execute("DELETE FROM knowledge_chunks")
            if self.fts_available:
                self.connection.execute("DELETE FROM knowledge_fts")
        self.index(chunks)

    @classmethod
    def refresh(
        cls,
        root: str | Path,
        *,
        max_file_bytes: int = _MAX_FILE_BYTES,
    ) -> IndexRefreshResult:
        """Build ``indexes/`` atomically from safe markdown files below *root*."""
        root_path = _safe_root(root)
        chunks, skipped = _collect_chunks(root_path, max_file_bytes=max_file_bytes)
        indexes = root_path / _INDEX_DIRECTORY
        indexes.mkdir(mode=0o700, exist_ok=True)
        database = indexes / _DATABASE_NAME
        chunks_file = indexes / _CHUNKS_NAME

        database_temp = _temporary_path(indexes, ".sqlite")
        chunks_temp = _temporary_path(indexes, ".jsonl")
        try:
            index = cls(database_temp)
            try:
                index.replace(chunks)
            finally:
                index.close()
            _write_chunks_jsonl(chunks_temp, chunks)
            os.replace(database_temp, database)
            os.replace(chunks_temp, chunks_file)
        finally:
            for temporary in (database_temp, chunks_temp):
                temporary.unlink(missing_ok=True)
        return IndexRefreshResult(root_path, database, chunks_file, len(chunks), tuple(skipped))

    @classmethod
    def default_knowledge_root(cls) -> Path:
        """Return a discoverable bundled seed directory for installed copies."""
        bundled = resources.files("ctf_os.resources").joinpath("knowledge")
        try:
            return Path(bundled)  # type: ignore[arg-type]
        except TypeError as exc:  # zip imports need a caller to materialize explicitly.
            raise OSError("bundled knowledge is not available as a local directory") from exc

    @classmethod
    def initialize_default_root(cls, target: str | Path) -> Path:
        """Copy bundled seed content to a missing local root, excluding indexes."""
        target_path = Path(target).expanduser()
        if target_path.exists():
            return _safe_root(target_path)
        source = cls.default_knowledge_root()
        if source.is_symlink() or not source.is_dir():
            raise OSError("bundled knowledge seed is unavailable")
        target_path.mkdir(parents=True, exist_ok=False)
        for path in sorted(source.rglob("*")):
            if path.is_symlink() or not path.is_file() or _INDEX_DIRECTORY in path.relative_to(source).parts:
                continue
            relative = path.relative_to(source)
            destination = target_path / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)
        return _safe_root(target_path)

    @classmethod
    def open_root(cls, root: str | Path) -> "KnowledgeIndex":
        """Open the persistent index for a root that was already refreshed."""
        root_path = _safe_root(root)
        database = root_path / _INDEX_DIRECTORY / _DATABASE_NAME
        if not database.is_file():
            raise FileNotFoundError(f"knowledge index not found: {database}; run `ctf-os knowledge index`")
        return cls(database)

    def retrieve(
        self,
        query: str,
        *,
        category: str | None = None,
        trust: str | Sequence[str] | None = None,
        include_reviewed: bool = False,
        limit: int = 5,
        challenge_name: str = "",
        description: str = "",
        failures: Sequence[str] = (),
        findings: Sequence[str] = (),
        strategy_seed: str = "",
    ) -> list[KnowledgeChunk]:
        """Return top chunks using challenge evidence, with stable tie breaking.

        ``query`` and the original keyword-only arguments remain compatible with
        the initial in-memory API.  Extra context lets callers weight a title,
        description, failures, findings, and strategy seed independently.
        """
        if limit <= 0:
            return []
        normalized_category = category.lower().strip() if category else None
        trusts = _normalize_trust_filter(trust, include_reviewed=include_reviewed)
        weighted_terms = _weighted_terms(
            query=query,
            challenge_name=challenge_name,
            description=description,
            failures=failures,
            findings=findings,
            strategy_seed=strategy_seed,
        )
        candidates = self._candidate_chunks(weighted_terms, normalized_category, trusts)
        ranked = [
            (self._score(chunk, weighted_terms, normalized_category), chunk)
            for chunk in candidates
        ]
        # Do not surface arbitrary zero-evidence chunks for a non-empty search.
        if weighted_terms:
            ranked = [item for item in ranked if item[0] > 0]
        return [chunk for _, chunk in sorted(ranked, key=lambda item: (-item[0], item[1].id))[:limit]]

    def query(
        self,
        *,
        category: str | None = None,
        trust: str | Sequence[str] | None = None,
        include_reviewed: bool = False,
        challenge_name: str = "",
        description: str = "",
        failures: Sequence[str] = (),
        findings: Sequence[str] = (),
        strategy_seed: str = "",
        limit: int = 5,
    ) -> list[KnowledgeChunk]:
        """Convenience API for structured challenge context."""
        return self.retrieve(
            "",
            category=category,
            trust=trust,
            include_reviewed=include_reviewed,
            limit=limit,
            challenge_name=challenge_name,
            description=description,
            failures=failures,
            findings=findings,
            strategy_seed=strategy_seed,
        )

    def _candidate_chunks(
        self, weighted_terms: dict[str, int], category: str | None, trusts: tuple[str, ...],
    ) -> list[KnowledgeChunk]:
        if not weighted_terms:
            return self._all_chunks(category, trusts)
        # FTS5 is used first to reduce the local candidate set.  A complete
        # deterministic scorer below handles evidence weights and tie breaks.
        if self.fts_available:
            try:
                terms = sorted(weighted_terms)
                match = " OR ".join(f'"{term.replace(chr(34), "")}"' for term in terms)
                sql = (
                    "SELECT DISTINCT c.* FROM knowledge_fts f "
                    "JOIN knowledge_chunks c ON c.id = f.id WHERE knowledge_fts MATCH ? "
                    f"AND c.trust IN ({','.join('?' for _ in trusts)})"
                )
                params: list[object] = [match, *trusts]
                if category:
                    sql += " AND (c.category = ? OR c.category = 'tools')"
                    params.append(category)
                sql += " ORDER BY c.id LIMIT 250"
                rows = list(self.connection.execute(sql, params))
                if rows:
                    return [self._row_to_chunk(row) for row in rows]
            except sqlite3.OperationalError:
                pass
        return self._all_chunks(category, trusts)

    def _all_chunks(self, category: str | None, trusts: tuple[str, ...]) -> list[KnowledgeChunk]:
        sql = f"SELECT * FROM knowledge_chunks WHERE trust IN ({','.join('?' for _ in trusts)})"
        params: list[object] = list(trusts)
        if category:
            sql += " AND (category = ? OR category = 'tools')"
            params.append(category)
        sql += " ORDER BY id"
        return [self._row_to_chunk(row) for row in self.connection.execute(sql, params)]

    @staticmethod
    def _score(chunk: KnowledgeChunk, terms: dict[str, int], category: str | None) -> int:
        evidence = 0
        haystack = " ".join((chunk.content, *chunk.tags, *chunk.tools)).casefold()
        for term, weight in terms.items():
            occurrences = haystack.count(term)
            if occurrences:
                evidence += weight * min(occurrences, 3)
                if term in {tag.casefold() for tag in chunk.tags}:
                    evidence += weight * 2
                if term in {tool.casefold() for tool in chunk.tools}:
                    evidence += weight
        # A category is a ranking signal, never evidence by itself when the
        # caller supplied search terms.  This keeps generated-index text and
        # unrelated queries from returning arbitrary category documents.
        if terms and not evidence:
            return 0
        return evidence + (12 if category and chunk.category == category else 2 if chunk.category == "tools" else 0)

    @staticmethod
    def _row_to_chunk(row: sqlite3.Row) -> KnowledgeChunk:
        try:
            provenance = json.loads(row["provenance"])
        except (KeyError, TypeError, json.JSONDecodeError):
            provenance = {}
        try:
            flags = tuple(json.loads(row["flags"]))
        except (KeyError, TypeError, json.JSONDecodeError):
            flags = ()
        try:
            links = tuple(json.loads(row["links"]))
        except (KeyError, TypeError, json.JSONDecodeError):
            links = ()
        return KnowledgeChunk(
            id=row["id"], source=row["source"], category=row["category"], content=row["content"],
            tags=tuple(filter(None, row["tags"].split(" "))), tools=tuple(filter(None, row["tools"].split(" "))),
            trust=row["trust"] if "trust" in row.keys() else "accepted",
            provenance=provenance if isinstance(provenance, dict) else {}, flags=flags,
            truncated=bool(row["truncated"]) if "truncated" in row.keys() else False, links=links,
        )


def _safe_root(root: str | Path) -> Path:
    candidate = Path(root).expanduser()
    if candidate.is_symlink() or not candidate.is_dir():
        raise ValueError(f"knowledge root must be a non-symlink directory: {candidate}")
    return candidate.resolve(strict=True)


def _collect_chunks(root: Path, *, max_file_bytes: int) -> tuple[list[KnowledgeChunk], list[str]]:
    chunks: list[KnowledgeChunk] = []
    skipped: list[str] = []
    external_records = _external_records(root)
    for path in sorted(root.rglob("*.md")):
        relative = path.relative_to(root)
        display = relative.as_posix()
        if _INDEX_DIRECTORY in relative.parts:
            continue
        external = _is_external_ctf_skills(relative)
        # The external subtree has no local-content fallback.  A missing,
        # malformed, or tampered manifest quarantines every Markdown file in
        # that subtree; only audit-validated registered paths can reach RAG.
        external_record = external_records.get(display) if external else None
        if external and external_record is None:
            skipped.append(display)
            continue
        if path.is_symlink() or not path.is_file():
            skipped.append(display)
            continue
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(root)
            size = path.stat().st_size
        except (OSError, ValueError):
            skipped.append(display)
            continue
        if size > max_file_bytes:
            skipped.append(display)
            continue
        try:
            raw = path.read_bytes()
            if b"\x00" in raw[:4096]:
                skipped.append(display)
                continue
            text = raw.decode("utf-8")
        except (OSError, UnicodeDecodeError):
            skipped.append(display)
            continue
        chunks.extend(_chunks_from_markdown(root, relative, text, external_record=external_record))
    return sorted(chunks, key=lambda chunk: chunk.id), skipped


def _chunks_from_markdown(
    root: Path, relative: Path, text: str, *, external_record: Mapping[str, object] | None = None,
) -> Iterator[KnowledgeChunk]:
    category = _category_for(relative)
    source = f"{root.name}/{relative.as_posix()}"
    external_sections = _external_sections(external_record)
    for section in classify_markdown_sections(text):
        raw_content = section.content
        if not raw_content or section.classification == "skipped":
            continue
        metadata = _chunk_metadata(relative, text, section, external_record, external_sections)
        if metadata is None:
            continue
        trust, flags, provenance = metadata
        content = raw_content[:_MAX_CHUNK_CHARS]
        # Preserve the pre-metadata identifier shape for a document preamble,
        # so existing local indexes can rebuild without needless ID churn.
        section_heading = relative.stem.replace("_", " ") if section.ordinal == 1 and section.heading == "document" else section.heading
        tags = _tags_for(relative, section_heading)
        digest = sha256(f"{source}\0{section_heading}\0{raw_content}".encode("utf-8")).hexdigest()[:12]
        slug = "-".join(_words(section_heading)[:4]) or "notes"
        identifier = f"{category}-{relative.stem.replace('_', '-')}-{section.ordinal:02d}-{slug}-{digest}"
        yield KnowledgeChunk(
            identifier, source, category, content, tags, _tools_for(relative, content), trust=trust,
            provenance=provenance, flags=flags, truncated=len(raw_content) > _MAX_CHUNK_CHARS,
            links=_external_links(raw_content),
        )


def _external_records(root: Path) -> dict[str, Mapping[str, object]]:
    """Return only records from an audit-validated canonical snapshot."""
    snapshot = root / "external" / "ctf-skills"
    audit = audit_snapshot(snapshot)
    if not audit.valid:
        return {}
    return {
        f"external/ctf-skills/{relative}": record
        for relative, record in audit.registered_files.items()
    }


def _is_external_ctf_skills(relative: Path) -> bool:
    return len(relative.parts) >= 3 and relative.parts[:2] == ("external", "ctf-skills")


def _external_sections(record: Mapping[str, object] | None) -> dict[int, Mapping[str, object]]:
    if not record or not isinstance(record.get("sections"), list):
        return {}
    return {
        value["ordinal"]: value for value in record["sections"]
        if isinstance(value, dict) and isinstance(value.get("ordinal"), int)
    }


def _chunk_metadata(
    relative: Path,
    text: str,
    section,
    external_record: Mapping[str, object] | None,
    external_sections: Mapping[int, Mapping[str, object]],
) -> tuple[str, tuple[str, ...], Mapping[str, object]] | None:
    flags = tuple(section.flags)
    provenance: dict[str, object] = {"kind": "local", "path": relative.as_posix()}
    trust = section.classification
    if external_record is None:
        return trust, flags, provenance
    expected_hash = external_record.get("sha256")
    if not isinstance(expected_hash, str) or sha256(text.encode("utf-8")).hexdigest() != expected_hash:
        return None
    imported = external_sections.get(section.ordinal)
    if not _section_metadata_matches(imported, section):
        return None
    trust = str(imported["classification"])
    imported_flags = imported["flags"]
    flags = tuple(sorted(set((*flags, *imported_flags))))
    upstream = _external_upstream(relative)
    provenance.update(upstream)
    provenance["kind"] = "external"
    provenance["original_path"] = str(external_record.get("original_path", ""))
    provenance["sha256"] = expected_hash
    return trust, flags, provenance


def _section_metadata_matches(record: Mapping[str, object] | None, section) -> bool:
    """Require the current section to match its reviewed manifest metadata."""
    if record is None:
        return False
    flags = record.get("flags")
    return (
        record.get("ordinal") == section.ordinal
        and record.get("heading") == section.heading
        and record.get("sha256") == section.sha256
        and record.get("classification") == section.classification
        and isinstance(flags, list)
        and all(isinstance(value, str) for value in flags)
        and tuple(flags) == section.flags
        and record.get("truncated") is False
    )


def _external_upstream(relative: Path) -> dict[str, object]:
    # The values below are fixed by the importer manifest; they are metadata,
    # not instructions to reach an upstream URL.
    return {"repository": "https://github.com/ljagiello/ctf-skills", "commit": "0a3a9c41bdef1ffb845e71cb53a7a6adbec85956"}


def _category_for(relative: Path) -> str:
    parts = relative.parts
    if len(parts) >= 4 and parts[:2] == ("external", "ctf-skills"):
        external_category = parts[2].removeprefix("ctf-")
        if external_category == "reverse":
            return "rev"
        if external_category in _CATEGORIES:
            return external_category
    if len(parts) >= 2 and parts[0] == "playbooks" and relative.stem in _CATEGORIES:
        return relative.stem
    if len(parts) >= 2 and parts[0] == "writeups" and parts[1].lower() in _CATEGORIES:
        return parts[1].lower()
    if parts and parts[0] == "tools":
        return "tools"
    return "misc"


def _tags_for(relative: Path, heading: str) -> tuple[str, ...]:
    words = list(_words(relative.stem.replace("_", " "))) + list(_words(heading))
    return tuple(dict.fromkeys(words))[:16]


def _tools_for(relative: Path, content: str) -> tuple[str, ...]:
    if relative.parts and relative.parts[0] == "tools":
        return (relative.stem.replace("_", "-"),)
    lowered = content.casefold()
    tools = [tool for tool in _TOOL_ALLOWLIST if re.search(rf"(?<![\w-]){re.escape(tool)}(?![\w-])", lowered)]
    return tuple(tools)


def _external_links(content: str) -> tuple[str, ...]:
    """Retain URLs solely as local metadata; callers must never fetch them."""
    return tuple(dict.fromkeys(match.group(0) for match in _URL_RE.finditer(content)))[:32]


def _normalize_trust_filter(trust: str | Sequence[str] | None, *, include_reviewed: bool) -> tuple[str, ...]:
    if trust is None:
        selected = {"accepted"}
    elif isinstance(trust, str):
        selected = {trust.casefold().strip()}
    else:
        selected = {value.casefold().strip() for value in trust}
    if include_reviewed:
        selected.add("reviewed")
    if not selected or not selected <= _TRUST_VALUES:
        valid = ", ".join(sorted(_TRUST_VALUES))
        raise ValueError(f"trust must be one of: {valid}")
    return tuple(sorted(selected))


def _weighted_terms(
    *, query: str, challenge_name: str, description: str, failures: Sequence[str], findings: Sequence[str], strategy_seed: str,
) -> dict[str, int]:
    weighted: dict[str, int] = {}
    for text, weight in (
        (query, 3),
        (challenge_name, 6),
        (description, 4),
        (" ".join(failures), 5),
        (" ".join(findings), 7),
        (strategy_seed, 5),
    ):
        for term in _words(text):
            weighted[term] = weighted.get(term, 0) + weight
    return weighted


def _words(text: str) -> tuple[str, ...]:
    return tuple(word.casefold() for word in _WORD_RE.findall(text) if len(word) > 1)


def _temporary_path(directory: Path, suffix: str) -> Path:
    descriptor, name = tempfile.mkstemp(prefix=".knowledge-", suffix=suffix, dir=directory)
    os.close(descriptor)
    return Path(name)


def _write_chunks_jsonl(path: Path, chunks: Sequence[KnowledgeChunk]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for chunk in chunks:
            handle.write(json.dumps({
                "id": chunk.id,
                "source": chunk.source,
                "category": chunk.category,
                "tags": list(chunk.tags),
                "tools": list(chunk.tools),
                "trust": chunk.trust,
                "provenance": dict(chunk.provenance),
                "flags": list(chunk.flags),
                "truncated": chunk.truncated,
                "links": list(chunk.links),
                "content": chunk.content,
            }, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
            handle.write("\n")


class PlaybookSelector:
    """Select category playbook chunks without reaching out to the internet."""

    _ALIASES = {category: category for category in _CATEGORIES}

    def select(self, category: str) -> str:
        normalized = category.lower().strip()
        return self._ALIASES.get(normalized, "misc")

    def retrieve(self, index: KnowledgeIndex, category: str, query: str = "") -> list[KnowledgeChunk]:
        selected = self.select(category)
        return index.retrieve(query or selected, category=selected)
