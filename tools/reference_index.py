#!/usr/bin/env python3
"""Build category indexes over pinned local reference repositories."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import html
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - preflight requires PyYAML.
    yaml = None


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "references.yaml"
LOCK = ROOT / "references.lock.json"
INDEX_DIR = ROOT / "docs" / "reference-index"
CATEGORIES = (
    "common",
    "pwn",
    "web",
    "rev",
    "crypto",
    "forensics",
    "stego",
    "mobile",
    "malware",
    "web3",
    "cloud-container",
    "ai-ml",
    "hardware-rf-side-channel",
    "osint",
    "jail",
    "programming",
    "misc",
    "hybrid",
)
SKIP_DIRS = {
    ".git",
    ".github",
    ".gradle",
    ".idea",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "site-packages",
    "target",
    "vendor",
    "venv",
}
TEXT_EXTENSIONS = {
    ".c",
    ".cc",
    ".cfg",
    ".cpp",
    ".cs",
    ".go",
    ".h",
    ".hpp",
    ".html",
    ".java",
    ".js",
    ".json",
    ".kt",
    ".md",
    ".py",
    ".rb",
    ".rst",
    ".rs",
    ".sage",
    ".sh",
    ".smali",
    ".sol",
    ".toml",
    ".ts",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}
INTERESTING_PARTS = {
    "attack",
    "attacks",
    "cheat",
    "cheatsheet",
    "ctf",
    "docs",
    "doc",
    "example",
    "examples",
    "exploit",
    "exploits",
    "payload",
    "payloads",
    "poc",
    "proof",
    "rule",
    "rules",
    "sample",
    "samples",
    "test",
    "tests",
    "tutorial",
    "vuln",
    "vulnerabilities",
}
KEYWORDS = {
    "aead",
    "apk",
    "api",
    "auth",
    "bof",
    "canary",
    "capa",
    "cbc",
    "coppersmith",
    "cisa",
    "csrf",
    "cve",
    "cvss",
    "cwe",
    "deserialize",
    "deserialization",
    "directory-traversal",
    "ecc",
    "format-string",
    "gadget",
    "heap",
    "idor",
    "jwt",
    "kev",
    "lattice",
    "lfi",
    "lsb",
    "nonce",
    "oauth",
    "oracle",
    "open-redirect",
    "overflow",
    "padding",
    "path-traversal",
    "prototype-pollution",
    "prompt-injection",
    "prng",
    "race",
    "reentrancy",
    "request-smuggling",
    "rfi",
    "rop",
    "rsa",
    "seccomp",
    "sqli",
    "ssrf",
    "ssti",
    "symbolic",
    "template",
    "traversal",
    "uaf",
    "upload",
    "web-cache",
    "xss",
    "xxe",
    "yara",
}


def fail(message: str, code: int = 1) -> None:
    print(f"reference_index: {message}", file=sys.stderr)
    raise SystemExit(code)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=str(MANIFEST))
    parser.add_argument("--lock", default=str(LOCK))
    parser.add_argument("--category", choices=CATEGORIES)
    parser.add_argument("--all", action="store_true", help="build every category index")
    parser.add_argument("--check", action="store_true", help="validate existing indexes without writing")
    parser.add_argument("--max-files-per-ref", type=int, default=80)
    return parser.parse_args()


def load_manifest(path: Path) -> list[dict[str, Any]]:
    if yaml is None:
        fail("PyYAML is required", code=2)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        fail(f"cannot read manifest: {exc}", code=2)
    except yaml.YAMLError as exc:
        fail(f"invalid manifest YAML: {exc}", code=2)
    refs = data.get("references") if isinstance(data, dict) else None
    if not isinstance(refs, list):
        fail("manifest must contain references list", code=2)
    return [ref for ref in refs if isinstance(ref, dict) and isinstance(ref.get("id"), str)]


def load_lock(path: Path) -> dict[str, dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        fail(f"cannot read lock: {exc}", code=2)
    except json.JSONDecodeError as exc:
        fail(f"invalid lock JSON: {exc}", code=2)
    refs = data.get("references") if isinstance(data, dict) else None
    if not isinstance(refs, list):
        fail("lock must contain references list", code=2)
    return {str(ref["id"]): ref for ref in refs if isinstance(ref, dict) and isinstance(ref.get("id"), str)}


def ref_categories(ref: dict[str, Any]) -> set[str]:
    value = ref.get("category")
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {str(item) for item in value if isinstance(item, str)}
    return set()


def category_selectors(category: str) -> set[str]:
    if category == "cloud-container":
        return {"common", "cloud", "container"}
    if category == "hardware-rf-side-channel":
        return {"common", "hardware-rf", "side-channel"}
    if category == "hybrid":
        return set(CATEGORIES) | {"cloud", "container", "hardware-rf", "side-channel"}
    return {"common", category}


def refs_for_category(refs: list[dict[str, Any]], category: str) -> list[dict[str, Any]]:
    selectors = category_selectors(category)
    selected = []
    seen = set()
    for ref in refs:
        if ref_categories(ref) & selectors:
            item_id = str(ref["id"])
            if item_id not in seen:
                selected.append(ref)
                seen.add(item_id)
    return selected


def safe_rel(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def materialized_root(ref: dict[str, Any], record: dict[str, Any]) -> Path | None:
    rel = record.get("materialized_path")
    if not isinstance(rel, str) or not rel:
        return None
    root = ROOT / rel
    if not root.is_dir():
        return None
    subpath = ref.get("source_subpath")
    if isinstance(subpath, str) and subpath.strip():
        candidate = root / subpath
        if candidate.exists():
            return candidate
    return root


def tokenize(text: str) -> list[str]:
    tokens: list[str] = []
    for item in re.findall(r"[A-Za-z0-9][A-Za-z0-9_+.-]{1,}", text):
        lowered = item.lower()
        tokens.append(lowered)
        tokens.extend(part for part in re.split(r"[^a-z0-9]+", lowered) if len(part) > 1)
    return tokens


def read_lines(path: Path, limit: int = 220) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return text.splitlines()[:limit]


def title_for(path: Path) -> str:
    if path.suffix.lower() in {".html", ".htm"}:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")[:50_000]
        except OSError:
            text = ""
        match = re.search(r"<title[^>]*>(.*?)</title>", text, flags=re.IGNORECASE | re.DOTALL)
        if match:
            title = re.sub(r"<[^>]+>", " ", match.group(1))
            title = re.sub(r"\s+", " ", html.unescape(title)).strip()
            if title:
                return title[:120]
    for line in read_lines(path, 80):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            return stripped.lstrip("#").strip()[:120]
        if len(stripped) < 120:
            return stripped
    return path.name


def line_count(path: Path) -> int:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return sum(1 for _ in handle)
    except OSError:
        return 0


def tags_for(category: str, ref_id: str, rel_file: str, title: str) -> list[str]:
    tokens = set(tokenize(f"{category} {ref_id} {rel_file} {title}"))
    tags = {category, ref_id}
    tags.update(token for token in tokens if token in KEYWORDS or token in INTERESTING_PARTS)
    return sorted(tags)


def kind_for(path: Path) -> str:
    parts = {part.lower() for part in path.parts}
    if "examples" in parts or "example" in parts or "samples" in parts:
        return "example"
    if "tests" in parts or "test" in parts:
        return "test"
    if "rules" in parts or path.suffix.lower() in {".yar", ".yara"}:
        return "rule"
    if path.suffix.lower() in {".md", ".rst", ".txt"}:
        return "doc"
    return "source"


def is_interesting_file(path: Path, root: Path) -> bool:
    if not path.is_file() or path.is_symlink():
        return False
    if path.stat().st_size > 350_000:
        return False
    suffix = path.suffix.lower()
    name = path.name.lower()
    if suffix not in TEXT_EXTENSIONS and not name.startswith(("readme", "license", "changelog")):
        return False
    rel_parts = safe_rel(path, root).lower().split("/")
    if any(part in SKIP_DIRS for part in rel_parts):
        return False
    if name.startswith("readme"):
        return True
    return bool(set(rel_parts) & INTERESTING_PARTS or set(tokenize("/".join(rel_parts))) & (INTERESTING_PARTS | KEYWORDS))


def iter_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        parts = set(path.relative_to(root).parts)
        if parts & SKIP_DIRS:
            continue
        if is_interesting_file(path, root):
            files.append(path)
    files.sort(key=lambda item: (0 if item.name.lower().startswith("readme") else 1, len(item.parts), item.as_posix()))
    return files


def overview_file(root: Path) -> Path | None:
    candidates = [
        root / "README.md",
        root / "README.rst",
        root / "README.txt",
        root / "docs" / "README.md",
        root / "doc" / "README.md",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    files = iter_files(root)
    return files[0] if files else None


def url_entry(category: str, ref: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    ref_id = str(ref["id"])
    return {
        "id": f"{ref_id}:overview",
        "category": category,
        "ref_id": ref_id,
        "license": str(ref.get("license", "")),
        "commit": str(record.get("commit", "")),
        "local_path": "",
        "file": "",
        "line_start": 0,
        "line_end": 0,
        "title": str(ref.get("why", ref_id)),
        "kind": "official-url",
        "tags": sorted({category, ref_id}),
        "applies_when": str(ref.get("why", "")),
        "query_terms": sorted(set(tokenize(f"{ref_id} {ref.get('why', '')} {ref.get('url', '')}"))),
        "url": str(ref.get("url", "")),
    }


def file_entry(category: str, ref: dict[str, Any], record: dict[str, Any], repo_root: Path, file_path: Path, entry_id: str) -> dict[str, Any]:
    ref_id = str(ref["id"])
    rel_file = safe_rel(file_path, repo_root)
    title = title_for(file_path)
    tags = tags_for(category, ref_id, rel_file, title)
    count = line_count(file_path)
    return {
        "id": entry_id,
        "category": category,
        "ref_id": ref_id,
        "license": str(ref.get("license", "")),
        "commit": str(record.get("commit", "")),
        "local_path": str(record.get("materialized_path", "")),
        "file": rel_file,
        "line_start": 1,
        "line_end": min(max(count, 1), 200),
        "title": title,
        "kind": kind_for(Path(rel_file)),
        "tags": tags,
        "applies_when": str(ref.get("why", "")),
        "query_terms": sorted(set(tokenize(f"{category} {ref_id} {rel_file} {title} {ref.get('why', '')}") + tags)),
        "url": str(ref.get("url", "")),
    }


def slug_for(path: Path) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", path.as_posix().lower()).strip("-")
    return value[:90] or "file"


def entries_for_ref(category: str, ref: dict[str, Any], record: dict[str, Any], max_files: int) -> list[dict[str, Any]]:
    repo_root = materialized_root(ref, record)
    if repo_root is None:
        return [url_entry(category, ref, record)]
    ref_id = str(ref["id"])
    entries: list[dict[str, Any]] = []

    def unique_entry_id(rel_file: str) -> str:
        base = f"{ref_id}:{slug_for(Path(rel_file))}"
        used = {str(entry["id"]) for entry in entries}
        if base not in used:
            return base
        digest = hashlib.sha1(rel_file.encode("utf-8")).hexdigest()[:8]
        candidate = f"{base}-{digest}"
        counter = 2
        while candidate in used:
            candidate = f"{base}-{digest}-{counter}"
            counter += 1
        return candidate

    overview = overview_file(repo_root)
    if overview is not None:
        entries.append(file_entry(category, ref, record, repo_root, overview, f"{ref_id}:overview"))
    seen = {entry["file"] for entry in entries}
    downloads = ref.get("download_files")
    if isinstance(downloads, list):
        for item in downloads:
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                continue
            file_path = repo_root / item["path"]
            if not file_path.is_file():
                continue
            rel_file = safe_rel(file_path, repo_root)
            if rel_file in seen:
                continue
            entries.append(file_entry(category, ref, record, repo_root, file_path, unique_entry_id(rel_file)))
            seen.add(rel_file)
            if len(entries) >= max_files:
                return entries
    for file_path in iter_files(repo_root):
        rel_file = safe_rel(file_path, repo_root)
        if rel_file in seen:
            continue
        entries.append(file_entry(category, ref, record, repo_root, file_path, unique_entry_id(rel_file)))
        seen.add(rel_file)
        if len(entries) >= max_files:
            break
    if not entries:
        entries.append(url_entry(category, ref, record))
    return entries


def build_category(category: str, refs: list[dict[str, Any]], lock: dict[str, dict[str, Any]], max_files: int) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for ref in refs_for_category(refs, category):
        record = lock.get(str(ref["id"]), {})
        entries.extend(entries_for_ref(category, ref, record, max_files))
    entries.sort(key=lambda entry: (str(entry["ref_id"]), str(entry["id"])))
    return {
        "schema_version": 1,
        "generated_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "category": category,
        "entries": entries,
    }


def validate_index(path: Path, category: str) -> None:
    if not path.is_file():
        fail(f"missing reference index: {path.relative_to(ROOT)}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid index JSON {path.relative_to(ROOT)}: {exc}", code=2)
    if not isinstance(data, dict) or data.get("category") != category:
        fail(f"index category mismatch: {path.relative_to(ROOT)}", code=2)
    entries = data.get("entries")
    if not isinstance(entries, list) or not entries:
        fail(f"index has no entries: {path.relative_to(ROOT)}", code=2)
    ids = set()
    for entry in entries:
        if not isinstance(entry, dict):
            fail(f"index entry is not object: {path.relative_to(ROOT)}", code=2)
        for key in ("id", "category", "ref_id", "title", "kind", "query_terms"):
            if key not in entry:
                fail(f"index entry missing {key}: {path.relative_to(ROOT)}", code=2)
        entry_id = str(entry["id"])
        if entry_id in ids:
            fail(f"duplicate index entry {entry_id}: {path.relative_to(ROOT)}", code=2)
        ids.add(entry_id)


def main() -> int:
    args = parse_args()
    categories = list(CATEGORIES if args.all or args.check else [args.category or "common"])
    if args.check:
        for category in categories:
            validate_index(INDEX_DIR / f"{category}.json", category)
        print(f"reference_index check ok: categories={len(categories)}")
        return 0

    manifest = Path(args.manifest)
    if not manifest.is_absolute():
        manifest = ROOT / manifest
    lock_path = Path(args.lock)
    if not lock_path.is_absolute():
        lock_path = ROOT / lock_path
    refs = load_manifest(manifest)
    lock = load_lock(lock_path)
    INDEX_DIR.mkdir(parents=True, exist_ok=True)
    for category in categories:
        data = build_category(category, refs, lock, max(1, args.max_files_per_ref))
        path = INDEX_DIR / f"{category}.json"
        path.write_text(json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")
        print(path.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
