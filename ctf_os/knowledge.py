"""Operator-controlled, immutable knowledge documents for one challenge.

CTF-OS never downloads research material on behalf of a model.  An operator
may add a local document together with its public source URL and optional
expected SHA-256.  The bytes are copied into the canonical challenge tree with
the same race-aware primitive used for proof evidence, and only a bounded text
excerpt is exposed to model context.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from ctf_os.models import ChallengeIdentity, utc_now
from ctf_os.sandbox.files import (
    ImmutableFile,
    SafeFileError,
    copy_bounded_regular,
    ensure_private_directory,
)
from ctf_os.store.atomic import atomic_write_json, atomic_write_text
from ctf_os.store.files import StateStore
from ctf_os.store.locks import FileLock

MAX_KNOWLEDGE_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_KNOWLEDGE_DOCUMENTS = 256
MAX_INDEX_BYTES = 4 * 1024 * 1024
MAX_EXTRACTED_TEXT_BYTES = 2 * 1024 * 1024
MAX_CONTEXT_EXCERPT_CHARS = 12_000
MAX_KNOWLEDGE_READ_BYTES = 64 * 1024
DEFAULT_KNOWLEDGE_READ_BYTES = 16 * 1024
MAX_KNOWLEDGE_SEARCH_RESULTS = 50
MAX_KNOWLEDGE_SEARCH_EXCERPT_CHARS = 1_000
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_TOKEN = re.compile(r"[0-9A-Za-z가-힣_]{2,64}")
_TEXT_SUFFIXES = frozenset(
    {
        ".c",
        ".cc",
        ".cpp",
        ".go",
        ".h",
        ".hpp",
        ".html",
        ".java",
        ".js",
        ".json",
        ".md",
        ".py",
        ".rs",
        ".rst",
        ".text",
        ".toml",
        ".ts",
        ".txt",
        ".yaml",
        ".yml",
    }
)


class KnowledgeError(ValueError):
    """A knowledge document or index violated the bounded provenance contract."""


@dataclass(frozen=True, slots=True)
class KnowledgeRecord:
    id: str
    title: str
    source_url: str
    sha256: str
    size_bytes: int
    document_path: str
    text_path: str | None
    text_sha256: str | None
    text_size_bytes: int | None
    added_at: str
    content_kind: str = "full_text"

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "title": self.title,
            "source_url": self.source_url,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "document_path": self.document_path,
            "text_path": self.text_path,
            "text_sha256": self.text_sha256,
            "text_size_bytes": self.text_size_bytes,
            "added_at": self.added_at,
            "content_kind": self.content_kind,
        }

    @classmethod
    def from_dict(cls, value: object) -> "KnowledgeRecord":
        if not isinstance(value, dict):
            raise KnowledgeError("knowledge record must be an object")
        try:
            record = cls(
                id=str(value["id"]),
                title=str(value["title"]),
                source_url=str(value["source_url"]),
                sha256=str(value["sha256"]).lower(),
                size_bytes=int(value["size_bytes"]),
                document_path=str(value["document_path"]),
                text_path=(
                    str(value["text_path"])
                    if value.get("text_path") is not None
                    else None
                ),
                text_sha256=(
                    str(value["text_sha256"]).lower()
                    if value.get("text_sha256") is not None
                    else None
                ),
                text_size_bytes=(
                    int(value["text_size_bytes"])
                    if value.get("text_size_bytes") is not None
                    else None
                ),
                added_at=str(value["added_at"]),
                content_kind=str(value.get("content_kind", "full_text")),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise KnowledgeError("invalid knowledge record") from error
        _validate_record(record)
        return record


@dataclass(frozen=True, slots=True)
class KnowledgeChunk:
    """One hash-verified, byte-bounded UTF-8 slice of extracted text."""

    record: KnowledgeRecord
    offset_bytes: int
    next_offset_bytes: int | None
    returned_bytes: int
    total_bytes: int
    text: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "document": self.record.to_dict(),
            "offset_unit": "utf8_bytes",
            "offset_bytes": self.offset_bytes,
            "next_offset_bytes": self.next_offset_bytes,
            "returned_bytes": self.returned_bytes,
            "total_bytes": self.total_bytes,
            "truncated": self.next_offset_bytes is not None,
            "text": self.text,
        }


def _validate_source_url(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\x00" in value
        or len(value.encode("utf-8")) > 4096
    ):
        raise KnowledgeError("source URL must be a bounded public URL")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or "?" in value
        or "#" in value
    ):
        raise KnowledgeError(
            "source URL must be an https URL without credentials, query, "
            "or fragment"
        )
    return value


def _validate_record(record: KnowledgeRecord) -> None:
    if not re.fullmatch(r"K-[0-9a-f]{32}", record.id):
        raise KnowledgeError("invalid knowledge record ID")
    if (
        not record.title.strip()
        or "\x00" in record.title
        or len(record.title.encode("utf-8")) > 512
    ):
        raise KnowledgeError("knowledge title must be 1..512 UTF-8 bytes")
    _validate_source_url(record.source_url)
    if not _SHA256.fullmatch(record.sha256):
        raise KnowledgeError("knowledge SHA-256 is invalid")
    if not 0 <= record.size_bytes <= MAX_KNOWLEDGE_DOCUMENT_BYTES:
        raise KnowledgeError("knowledge document size is out of bounds")
    if record.content_kind not in {"full_text", "source", "notes"}:
        raise KnowledgeError("unsupported knowledge content kind")
    expected_document = f"documents/{record.id}.bin"
    if record.document_path != expected_document:
        raise KnowledgeError("knowledge document path is not canonical")
    expected_text = f"text/{record.id}.txt"
    if record.text_path not in {None, expected_text}:
        raise KnowledgeError("knowledge text path is not canonical")
    if record.text_path is None:
        if record.text_sha256 is not None or record.text_size_bytes is not None:
            raise KnowledgeError("binary knowledge record has text metadata")
    elif (
        record.text_sha256 is None
        or not _SHA256.fullmatch(record.text_sha256)
        or record.text_size_bytes is None
        or not 0 <= record.text_size_bytes <= MAX_EXTRACTED_TEXT_BYTES
    ):
        raise KnowledgeError("knowledge text metadata is invalid")


def _read_bounded_regular(path: Path, maximum_bytes: int) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise KnowledgeError(f"cannot open knowledge file safely: {path}") from error
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > maximum_bytes:
            raise KnowledgeError("knowledge file is not a bounded regular file")
        chunks = bytearray()
        while len(chunks) <= maximum_bytes:
            block = os.read(
                descriptor,
                min(1024 * 1024, maximum_bytes + 1 - len(chunks)),
            )
            if not block:
                break
            chunks.extend(block)
        if len(chunks) > maximum_bytes:
            raise KnowledgeError("knowledge file exceeds its size bound")
        after = os.fstat(descriptor)
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise KnowledgeError("knowledge file changed while reading")
        return bytes(chunks)
    finally:
        os.close(descriptor)


def _load_index(root: Path) -> tuple[KnowledgeRecord, ...]:
    path = root / "index.json"
    if not path.exists():
        return ()
    raw = _read_bounded_regular(path, MAX_INDEX_BYTES)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise KnowledgeError("knowledge index is invalid JSON") from error
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != 1
        or not isinstance(value.get("documents"), list)
    ):
        raise KnowledgeError("knowledge index has an unsupported schema")
    records = tuple(
        KnowledgeRecord.from_dict(item) for item in value["documents"]
    )
    if len(records) > MAX_KNOWLEDGE_DOCUMENTS:
        raise KnowledgeError("knowledge index contains too many documents")
    if len({record.id for record in records}) != len(records):
        raise KnowledgeError("knowledge index contains duplicate IDs")
    return records


def _write_index(root: Path, records: tuple[KnowledgeRecord, ...]) -> None:
    atomic_write_json(
        root / "index.json",
        {
            "schema_version": 1,
            "documents": [record.to_dict() for record in records],
        },
        mode=0o600,
    )


def _extract_text(snapshot: ImmutableFile, original_suffix: str) -> str | None:
    if original_suffix.lower() not in _TEXT_SUFFIXES:
        return None
    raw = _read_bounded_regular(snapshot.path, MAX_EXTRACTED_TEXT_BYTES)
    try:
        text = raw.decode("utf-8")
    except UnicodeError as error:
        raise KnowledgeError(
            "text knowledge documents must be valid UTF-8"
        ) from error
    return text.replace("\x00", "�")


def _verified_bytes(
    root: Path,
    locator: str,
    *,
    expected_sha256: str,
    expected_size: int,
    maximum_bytes: int,
) -> bytes:
    raw = _read_bounded_regular(root / locator, maximum_bytes)
    if len(raw) != expected_size:
        raise KnowledgeError(f"knowledge file size mismatch: {locator}")
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise KnowledgeError(f"knowledge file hash mismatch: {locator}")
    return raw


def _verified_text(root: Path, record: KnowledgeRecord) -> str | None:
    """Reverify both immutable source and extracted text before model access."""

    _verified_bytes(
        root,
        record.document_path,
        expected_sha256=record.sha256,
        expected_size=record.size_bytes,
        maximum_bytes=MAX_KNOWLEDGE_DOCUMENT_BYTES,
    )
    if record.text_path is None:
        return None
    assert record.text_sha256 is not None and record.text_size_bytes is not None
    raw = _verified_bytes(
        root,
        record.text_path,
        expected_sha256=record.text_sha256,
        expected_size=record.text_size_bytes,
        maximum_bytes=MAX_EXTRACTED_TEXT_BYTES,
    )
    try:
        return raw.decode("utf-8")
    except UnicodeError as error:
        raise KnowledgeError("verified knowledge text is not valid UTF-8") from error


def _query_tokens(query: str) -> tuple[str, ...]:
    return tuple(sorted({token.casefold() for token in _TOKEN.findall(query)}))


def _score_text(
    record: KnowledgeRecord,
    text: str,
    tokens: tuple[str, ...],
) -> int:
    title = record.title.casefold()
    source = record.source_url.casefold()
    folded = text.casefold()
    return sum(
        8 * title.count(token)
        + 3 * source.count(token)
        + min(20, folded.count(token))
        for token in tokens
    )


def _matching_excerpt(
    text: str,
    tokens: tuple[str, ...],
    *,
    maximum_chars: int,
) -> tuple[str, int] | None:
    folded = text.casefold()
    first = min(
        (
            folded.find(token)
            for token in tokens
            if folded.find(token) >= 0
        ),
        default=-1,
    )
    if first < 0:
        return None
    before = min(maximum_chars // 4, first)
    start = first - before
    excerpt = text[start : start + maximum_chars]
    leading = len(excerpt) - len(excerpt.lstrip())
    start += leading
    return excerpt.strip(), start


def _context_excerpt(
    record: KnowledgeRecord,
    text: str,
    tokens: tuple[str, ...],
    query: str,
    *,
    maximum_chars: int = 4_000,
) -> tuple[str, int]:
    matched = _matching_excerpt(
        text,
        tokens,
        maximum_chars=maximum_chars,
    )
    if matched is not None:
        return matched
    if len(text) <= maximum_chars:
        return text.strip(), len(text) - len(text.lstrip())

    # A document with no lexical match still gets a deterministic inspection
    # window. Its position depends on the active solve query and document hash,
    # avoiding the old permanent first-4K bias without introducing retrieval
    # services or automatic downloads.
    seed = hashlib.sha256(
        f"{query}\0{record.sha256}".encode("utf-8")
    ).digest()
    start = int.from_bytes(seed[:8], "big") % (len(text) - maximum_chars + 1)
    excerpt = text[start : start + maximum_chars]
    leading = len(excerpt) - len(excerpt.lstrip())
    return excerpt.strip(), start + leading


class KnowledgeStore:
    """Immutable, challenge-scoped local research storage."""

    def __init__(self, state_store: StateStore) -> None:
        self.state_store = state_store

    def _root(self, identity: ChallengeIdentity) -> Path:
        return ensure_private_directory(
            self.state_store.challenge_paths(identity).knowledge
        )

    def _read_root(self, identity: ChallengeIdentity) -> Path:
        """Resolve the existing knowledge root without creating/chmodding it."""

        root = self.state_store.challenge_paths(identity).knowledge
        try:
            metadata = root.stat(follow_symlinks=False)
        except OSError as error:
            raise KnowledgeError(
                "challenge knowledge directory is unavailable"
            ) from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or root.is_symlink()
            or metadata.st_uid != os.geteuid()
        ):
            raise KnowledgeError(
                "challenge knowledge directory is not a trusted directory"
            )
        return root

    def list(self, identity: ChallengeIdentity) -> tuple[KnowledgeRecord, ...]:
        root = self._read_root(identity)
        if not (root / "index.json").exists():
            return ()
        with FileLock(
            root / ".lock",
            shared=True,
            create=False,
        ) as read_lock:
            read_lock.acquire()
            return _load_index(root)

    def add(
        self,
        identity: ChallengeIdentity,
        source_file: Path,
        *,
        source_url: str,
        title: str | None = None,
        expected_sha256: str | None = None,
        content_kind: str = "full_text",
    ) -> KnowledgeRecord:
        self.state_store.load(identity)
        public_source = _validate_source_url(source_url)
        source = Path(source_file).expanduser()
        try:
            before = source.stat(follow_symlinks=False)
        except OSError as error:
            raise KnowledgeError(f"cannot inspect knowledge source: {source}") from error
        if source.is_symlink() or not stat.S_ISREG(before.st_mode):
            raise KnowledgeError("knowledge source must be a regular non-symlink file")
        if before.st_size > MAX_KNOWLEDGE_DOCUMENT_BYTES:
            raise KnowledgeError("knowledge source exceeds 64 MiB")
        if expected_sha256 is not None and not _SHA256.fullmatch(expected_sha256):
            raise KnowledgeError("expected SHA-256 must contain 64 hex digits")
        selected_title = title if title is not None else source.name
        if content_kind not in {"full_text", "source", "notes"}:
            raise KnowledgeError("unsupported knowledge content kind")

        root = self._root(identity)
        documents = ensure_private_directory(root / "documents")
        text_root = ensure_private_directory(root / "text")
        record_id = f"K-{uuid.uuid4().hex}"
        destination = documents / f"{record_id}.bin"
        text_destination = text_root / f"{record_id}.txt"
        try:
            try:
                snapshot = copy_bounded_regular(
                    source.parent.resolve(strict=True),
                    source.name,
                    destination,
                    maximum_bytes=MAX_KNOWLEDGE_DOCUMENT_BYTES,
                    expected_sha256=expected_sha256,
                    mode=0o400,
                )
            except (OSError, SafeFileError) as error:
                raise KnowledgeError(str(error)) from error
            extracted = _extract_text(snapshot, source.suffix)
            text_path: str | None = None
            text_sha256: str | None = None
            text_size_bytes: int | None = None
            if extracted is not None:
                atomic_write_text(text_destination, extracted, mode=0o400)
                text_path = f"text/{record_id}.txt"
                encoded_text = extracted.encode("utf-8")
                text_sha256 = hashlib.sha256(encoded_text).hexdigest()
                text_size_bytes = len(encoded_text)
            record = KnowledgeRecord(
                id=record_id,
                title=selected_title,
                source_url=public_source,
                sha256=snapshot.sha256,
                size_bytes=snapshot.size_bytes,
                document_path=f"documents/{record_id}.bin",
                text_path=text_path,
                text_sha256=text_sha256,
                text_size_bytes=text_size_bytes,
                added_at=utc_now(),
                content_kind=content_kind,
            )
            _validate_record(record)
            write_lock = FileLock(root / ".lock")
            try:
                # Install the caller-side cleanup guard before acquire().
                # A BaseException at FileLock.acquire's return handoff must
                # not leave this exact lock held through verification below.
                write_lock.acquire()
                records = _load_index(root)
                if len(records) >= MAX_KNOWLEDGE_DOCUMENTS:
                    raise KnowledgeError(
                        "challenge already has the maximum knowledge documents"
                    )
                duplicate = next(
                    (
                        item
                        for item in records
                        if item.sha256 == record.sha256
                        and item.source_url == record.source_url
                    ),
                    None,
                )
                if duplicate is not None:
                    destination.unlink(missing_ok=True)
                    if text_path is not None:
                        (root / text_path).unlink(missing_ok=True)
                    return duplicate
                _write_index(root, (*records, record))
            finally:
                active_error = sys.exception()
                try:
                    write_lock.release()
                except BaseException as release_error:
                    if (
                        active_error is not None
                        and not isinstance(active_error, Exception)
                    ):
                        active_error.add_note(
                            "knowledge write lock release failed: "
                            f"{release_error}"
                        )
                    else:
                        raise
            return record
        except BaseException as add_error:
            try:
                with FileLock(
                    root / ".lock",
                    shared=True,
                ) as verification_lock:
                    verification_lock.acquire()
                    committed = any(
                        item.id == record_id
                        for item in _load_index(root)
                    )
            except BaseException as verification_error:
                cleanup_failure = KnowledgeError(
                    "knowledge add failed and the canonical index could not be "
                    "verified; new files were preserved"
                )
                if isinstance(add_error, Exception):
                    raise cleanup_failure from add_error
                add_error.add_note(
                    f"{cleanup_failure}: {verification_error}"
                )
                raise
            cleanup_errors: list[str] = []
            if not committed:
                for created_path in (
                    destination,
                    text_destination,
                ):
                    try:
                        created_path.unlink(missing_ok=True)
                    except BaseException as cleanup_error:
                        cleanup_errors.append(
                            f"{created_path.name}: "
                            f"{type(cleanup_error).__name__}: {cleanup_error}"
                        )
            if cleanup_errors:
                cleanup_failure = KnowledgeError(
                    "knowledge add failed and exact file cleanup failed: "
                    + "; ".join(cleanup_errors)
                )
                if isinstance(add_error, Exception):
                    raise cleanup_failure from add_error
                add_error.add_note(str(cleanup_failure))
            raise

    def _search_results(
        self,
        identity: ChallengeIdentity,
        query: str,
        *,
        limit: int = 10,
    ) -> tuple[tuple[KnowledgeRecord, float, str, int], ...]:
        if (
            not isinstance(query, str)
            or not query.strip()
            or len(query.encode("utf-8")) > 4096
        ):
            raise KnowledgeError("knowledge query must be 1..4096 UTF-8 bytes")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_KNOWLEDGE_SEARCH_RESULTS
        ):
            raise KnowledgeError("knowledge search limit must be between 1 and 50")
        root = self._read_root(identity)
        tokens = _query_tokens(query)
        if not tokens:
            raise KnowledgeError("knowledge query has no searchable tokens")
        results: list[tuple[KnowledgeRecord, float, str, int]] = []
        if not (root / "index.json").exists():
            return ()
        with FileLock(
            root / ".lock",
            shared=True,
            create=False,
        ) as search_lock:
            search_lock.acquire()
            for record in _load_index(root):
                text = _verified_text(root, record) or ""
                score = _score_text(record, text, tokens)
                if score <= 0:
                    continue
                matched = _matching_excerpt(
                    text,
                    tokens,
                    maximum_chars=MAX_KNOWLEDGE_SEARCH_EXCERPT_CHARS,
                )
                excerpt, offset_chars = matched if matched is not None else ("", 0)
                results.append(
                    (
                        record,
                        float(score),
                        excerpt,
                        len(text[:offset_chars].encode("utf-8")),
                    )
                )
        results.sort(key=lambda item: (-item[1], item[0].id))
        return tuple(results[:limit])

    def search(
        self,
        identity: ChallengeIdentity,
        query: str,
        *,
        limit: int = 10,
    ) -> tuple[tuple[KnowledgeRecord, float, str], ...]:
        return tuple(
            (record, score, excerpt)
            for record, score, excerpt, _offset_bytes
            in self._search_results(identity, query, limit=limit)
        )

    def search_envelope(
        self,
        identity: ChallengeIdentity,
        query: str,
        *,
        limit: int = 10,
    ) -> dict[str, object]:
        """Return a bounded, provenance-rich search response for model tools."""

        matches = self._search_results(identity, query, limit=limit)
        results: list[dict[str, object]] = []
        for record, score, excerpt, excerpt_offset_bytes in matches:
            results.append(
                {
                    "document": record.to_dict(),
                    "score": score,
                    "excerpt": excerpt,
                    "excerpt_offset_bytes": excerpt_offset_bytes,
                }
            )
        return {
            "schema_version": 1,
            "query": query,
            "returned": len(results),
            "results": results,
        }

    def read(
        self,
        identity: ChallengeIdentity,
        document_id: str,
        *,
        offset_bytes: int = 0,
        max_bytes: int = DEFAULT_KNOWLEDGE_READ_BYTES,
    ) -> KnowledgeChunk:
        """Read one UTF-8-boundary-aligned chunk after full provenance checks."""

        if not isinstance(document_id, str) or not re.fullmatch(
            r"K-[0-9a-f]{32}", document_id
        ):
            raise KnowledgeError("invalid knowledge document ID")
        if (
            isinstance(offset_bytes, bool)
            or not isinstance(offset_bytes, int)
            or offset_bytes < 0
            or offset_bytes > MAX_EXTRACTED_TEXT_BYTES
        ):
            raise KnowledgeError(
                "knowledge read offset_bytes must be between 0 and 2 MiB"
            )
        if (
            isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
            or not 1 <= max_bytes <= MAX_KNOWLEDGE_READ_BYTES
        ):
            raise KnowledgeError(
                "knowledge read max_bytes must be between 1 and 65536"
            )

        root = self._read_root(identity)
        if not (root / "index.json").exists():
            raise KnowledgeError("knowledge document does not exist")
        with FileLock(
            root / ".lock",
            shared=True,
            create=False,
        ) as read_lock:
            read_lock.acquire()
            record = next(
                (
                    item
                    for item in _load_index(root)
                    if item.id == document_id
                ),
                None,
            )
            if record is None:
                raise KnowledgeError("knowledge document does not exist")
            text = _verified_text(root, record)
            if text is None:
                raise KnowledgeError(
                    "knowledge document has no operator-approved text extraction"
                )
            raw = text.encode("utf-8")

        if offset_bytes > len(raw):
            raise KnowledgeError("knowledge read offset_bytes exceeds text size")
        try:
            raw[:offset_bytes].decode("utf-8")
        except UnicodeError as error:
            raise KnowledgeError(
                "knowledge read offset_bytes must be a UTF-8 boundary"
            ) from error

        end = min(len(raw), offset_bytes + max_bytes)
        while end > offset_bytes:
            try:
                chunk_text = raw[offset_bytes:end].decode("utf-8")
                break
            except UnicodeDecodeError as error:
                if error.end != len(raw[offset_bytes:end]):
                    raise KnowledgeError(
                        "verified knowledge text is not valid UTF-8"
                    ) from error
                end -= 1
        else:
            if offset_bytes < len(raw):
                raise KnowledgeError(
                    "knowledge read max_bytes is too small for the next "
                    "UTF-8 code point"
                )
            chunk_text = ""
        return KnowledgeChunk(
            record=record,
            offset_bytes=offset_bytes,
            next_offset_bytes=end if end < len(raw) else None,
            returned_bytes=end - offset_bytes,
            total_bytes=len(raw),
            text=chunk_text,
        )


def knowledge_context(
    knowledge_root: Path,
    *,
    max_chars: int = MAX_CONTEXT_EXCERPT_CHARS,
    query: str = "",
) -> tuple[list[str], int]:
    """Return bounded provenance-rich context lines without failing a solve.

    A corrupt index is represented as one safe warning line.  It never causes
    the model to receive unverified bytes, and the operator can repair the
    index before the next run.
    """

    if max_chars < 1024:
        raise ValueError("knowledge context bound must be at least 1024")
    try:
        root = ensure_private_directory(knowledge_root)
        with FileLock(root / ".lock", shared=True) as context_lock:
            context_lock.acquire()
            records = _load_index(root)
            tokens = _query_tokens(query)
            ranked: list[
                tuple[int, str, KnowledgeRecord, str | None, int]
            ] = []
            for record in records:
                text = _verified_text(root, record)
                score = _score_text(record, text or "", tokens)
                excerpt = ""
                excerpt_offset_bytes = 0
                if text:
                    excerpt, excerpt_offset_chars = _context_excerpt(
                        record,
                        text,
                        tokens,
                        query,
                    )
                    excerpt_offset_bytes = len(
                        text[:excerpt_offset_chars].encode("utf-8")
                    )
                ranked.append(
                    (
                        score,
                        record.id,
                        record,
                        excerpt or None,
                        excerpt_offset_bytes,
                    )
                )
            ranked.sort(key=lambda item: (-item[0], item[1]))
            lines: list[str] = []
            used = 0
            omitted = 0
            for index, (
                score,
                _record_id,
                record,
                excerpt,
                excerpt_offset_bytes,
            ) in enumerate(ranked):
                heading = (
                    f"`{record.id}` [{record.content_kind}] {record.title}; "
                    f"source={record.source_url}; sha256={record.sha256}; "
                    f"size={record.size_bytes}; "
                    f"path=`knowledge/{record.document_path}`; "
                    f"selection_score={score}"
                )
                if record.text_path is not None:
                    heading += (
                        f"; text_sha256={record.text_sha256}; "
                        f"text_size={record.text_size_bytes}; "
                        f"text_path=`knowledge/{record.text_path}`"
                    )
                safe_excerpt = (
                    excerpt.replace("\r", "\\r") if excerpt else ""
                )
                entry = heading + (
                    (
                        f"\n  excerpt_offset_bytes={excerpt_offset_bytes}; "
                        f"excerpt: {safe_excerpt}"
                    )
                    if excerpt
                    else ""
                )
                if used + len(entry) > max_chars:
                    omitted = len(ranked) - index
                    break
                lines.append(entry)
                used += len(entry)
            return lines, omitted
    except (KnowledgeError, OSError, SafeFileError) as error:
        digest = hashlib.sha256(str(error).encode("utf-8")).hexdigest()[:12]
        return [f"knowledge index unavailable (error-id={digest})"], 0


__all__ = [
    "DEFAULT_KNOWLEDGE_READ_BYTES",
    "MAX_CONTEXT_EXCERPT_CHARS",
    "MAX_KNOWLEDGE_READ_BYTES",
    "MAX_KNOWLEDGE_SEARCH_RESULTS",
    "KnowledgeChunk",
    "KnowledgeError",
    "KnowledgeRecord",
    "KnowledgeStore",
    "knowledge_context",
]
