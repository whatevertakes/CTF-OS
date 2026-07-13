"""Deep-ready, deterministic intake for every challenge in one contest."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import mimetypes
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from .archive import ArchiveError, ArchiveLimits, bounded_source_files, copy_tree_without_links, extract_archive
from .contest import ChallengeSpec, ContestManifest, discover_contests, select_contest
from .sandbox.network import parse_remotes
from .workspace import atomic_json, atomic_text, bind_input_fingerprint, challenge_root


ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.bz2", ".tbz2", ".7z", ".rar")


def run_intake(repo: str | Path, contest_selector: str | None = None) -> dict[str, object]:
    root = Path(repo).resolve()
    manifest = select_contest(discover_contests(root / "incoming"), contest_selector)
    records = [_inspect_challenge(root, manifest, challenge) for challenge in manifest.challenges]
    payload: dict[str, object] = {
        "schema_version": 1, "generated_at": datetime.now(timezone.utc).isoformat(),
        "contest": manifest.to_dict(), "challenges": records,
        "summary": {
            "total": len(records), "ready": sum(r["status"] == "READY" for r in records),
            "blocked": sum(r["status"] == "BLOCKED" for r in records),
        },
    }
    contest_output = root / "output" / manifest.slug
    atomic_json(contest_output / "intake.json", payload)
    atomic_text(contest_output / "INTAKE.md", render_intake_markdown(payload))
    return payload


def _inspect_challenge(root: Path, manifest: ContestManifest, challenge: ChallengeSpec) -> dict[str, object]:
    destination = challenge_root(root, manifest, challenge)
    base: dict[str, object] = challenge.to_dict() | {
        "status": "BLOCKED", "blockers": [], "authorized_targets": [],
        "source_paths": [], "files": [], "archives": [], "docker": {},
        "runtime": [], "subtype": None, "attack_surface": [], "hypotheses": [],
        "recommended_tools": [], "read_paths": [], "context_path": str(destination / "CONTEXT.md"),
        "workspace_path": str(destination), "prepared_input": str(destination / "input"),
        "source_fingerprint": None, "prepared_fingerprint": None,
    }
    try:
        base["authorized_targets"] = [target.to_dict() for target in parse_remotes(challenge.remotes)]
        sources = _match_sources(manifest, challenge)
        base["source_paths"] = [str(path) for path in sources]
        if not sources and not challenge.remotes:
            raise ValueError("contest.md entry has no matching directory/archive and no authorized remote")
        input_dir, archive_records, fingerprint, prepared_fingerprint = _materialize(destination, challenge, sources)
        base["archives"] = archive_records
        base["source_fingerprint"] = fingerprint
        base["prepared_fingerprint"] = prepared_fingerprint
        files = [_inspect_file(input_dir, path) for path in _regular_files(input_dir)] if input_dir.exists() else []
        base["files"] = files
        preflight = _preflight(challenge, input_dir, files)
        base.update(preflight)
        base["read_paths"] = [str(manifest.path), str(destination / "CONTEXT.md"), str(input_dir)]
        base["status"] = "READY"
        destination.mkdir(parents=True, exist_ok=True)
        bind_input_fingerprint(destination, challenge, fingerprint)
        atomic_text(destination / "CONTEXT.md", render_context(manifest, base))
    except Exception as exc:
        base["blockers"] = [str(exc)]
        destination.mkdir(parents=True, exist_ok=True)
        atomic_text(destination / "CONTEXT.md", render_context(manifest, base))
    return base


def _match_sources(manifest: ContestManifest, challenge: ChallengeSpec) -> list[Path]:
    category_root = manifest.path.parent / challenge.category
    if not category_root.exists() and challenge.category == "forensic":
        alias = manifest.path.parent / "forensics"
        category_root = alias if alias.exists() else category_root
    if not category_root.is_dir() or category_root.is_symlink():
        return []
    wanted = {challenge.name.casefold(), challenge.workspace_name.casefold()}
    matches: list[Path] = []
    for entry in category_root.iterdir():
        if entry.is_symlink():
            continue
        if entry.is_dir() and entry.name.casefold() in wanted:
            matches.append(entry)
            continue
        if entry.is_file():
            lower = entry.name.casefold()
            for suffix in ARCHIVE_SUFFIXES:
                if lower.endswith(suffix) and lower[:-len(suffix)] in wanted:
                    matches.append(entry)
                    break
    return sorted(matches, key=lambda path: path.name.casefold())


def _materialize(destination: Path, challenge: ChallengeSpec, sources: list[Path]) -> tuple[Path, list[dict[str, object]], str, str]:
    fingerprint = _source_fingerprint(challenge, sources)
    input_dir = destination / "input"
    marker = destination / ".input-fingerprint"
    if input_dir.is_symlink() or marker.is_symlink():
        raise ArchiveError("prepared input or fingerprint marker must not be a symlink")
    if input_dir.is_dir() and marker.is_file() and marker.read_text() == fingerprint:
        metadata_path = destination / ".archive-metadata.json"
        cached = json.loads(metadata_path.read_text(encoding="utf-8")) if metadata_path.is_file() else _archive_metadata(sources)
        return input_dir, cached, fingerprint, prepared_tree_fingerprint(input_dir)
    destination.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".input-", dir=destination))
    archives: list[dict[str, object]] = []
    try:
        for source in sources:
            if source.is_dir():
                copy_tree_without_links(source, staging)
            else:
                lower = source.name.casefold()
                if lower.endswith((".7z", ".rar")):
                    raise ArchiveError(f"{source.name}: safe built-in extraction is unavailable; unpack it into a named directory")
                members = extract_archive(source, staging)
                archives.append({"path": str(source), "sha256": _sha256(source), "members": members, "extracted": True})
            prepared_tree_fingerprint(staging)
        _make_read_only(staging)
        old = destination / ".old-input"
        if old.exists():
            _remove_generated_tree(old)
        if input_dir.exists():
            os.replace(input_dir, old)
        os.replace(staging, input_dir)
        if old.exists():
            _remove_generated_tree(old)
        atomic_text(marker, fingerprint)
        atomic_json(destination / ".archive-metadata.json", archives)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return input_dir, archives, fingerprint, prepared_tree_fingerprint(input_dir)


def _source_fingerprint(challenge: ChallengeSpec, sources: list[Path]) -> str:
    digest = hashlib.sha256(json.dumps(challenge.to_dict(), ensure_ascii=False, sort_keys=True).encode())
    for source in sources:
        digest.update(source.name.encode())
        if source.is_file():
            digest.update(bytes.fromhex(_sha256(source)))
        else:
            total = 0
            limits = ArchiveLimits()
            for path in bounded_source_files(source, limits):
                size = path.stat().st_size
                if size > limits.max_file_bytes:
                    raise ArchiveError(f"source file exceeds size limit: {path.relative_to(source)}")
                total += size
                if total > limits.max_total_bytes:
                    raise ArchiveError("source directory exceeds total size limit")
                digest.update(path.relative_to(source).as_posix().encode())
                digest.update(bytes.fromhex(_sha256(path)))
    return digest.hexdigest()


def current_source_fingerprint(manifest: ContestManifest, challenge: ChallengeSpec) -> str:
    return _source_fingerprint(challenge, _match_sources(manifest, challenge))


def prepared_tree_fingerprint(root: Path) -> str:
    digest = hashlib.sha256()
    total = 0
    limits = ArchiveLimits()
    for path in bounded_source_files(root, limits):
        size = path.stat().st_size
        if size > limits.max_file_bytes:
            raise ArchiveError(f"prepared file exceeds size limit: {path.relative_to(root)}")
        total += size
        if total > limits.max_total_bytes:
            raise ArchiveError("prepared input exceeds total size limit")
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(bytes.fromhex(_sha256(path)))
    return digest.hexdigest()


def _archive_metadata(sources: list[Path]) -> list[dict[str, object]]:
    return [{"path": str(path), "sha256": _sha256(path), "extracted": True} for path in sources if path.is_file()]


def _regular_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    result: list[Path] = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ArchiveError(f"symlink found in prepared input: {path}")
        if path.is_file():
            result.append(path)
    return sorted(result, key=lambda path: path.relative_to(root).as_posix())


def _inspect_file(root: Path, path: Path) -> dict[str, object]:
    kind = _command_output(["file", "-b", str(path)]) or "unknown"
    mime = _command_output(["file", "-b", "--mime-type", str(path)]) or mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    record: dict[str, object] = {
        "path": path.relative_to(root).as_posix(), "size": path.stat().st_size,
        "sha256": _sha256(path), "mime": mime, "kind": kind,
    }
    with path.open("rb") as handle:
        magic = handle.read(4)
    if magic == b"\x7fELF":
        header = _command_output(["readelf", "-h", str(path)], limit=64_000)
        program = _command_output(["readelf", "-W", "-l", str(path)], limit=64_000)
        dynamic = _command_output(["readelf", "-W", "-d", str(path)], limit=64_000)
        record["elf"] = {
            "architecture": _readelf_value(header, "Machine"),
            "type": _readelf_value(header, "Type"),
            "nx": "GNU_STACK" in program and "RWE" not in program,
            "pie": "DYN" in (_readelf_value(header, "Type") or ""),
            "relro": "full" if "BIND_NOW" in dynamic else ("partial" if "GNU_RELRO" in program else "none"),
            "stripped": "stripped" in kind.casefold(),
        }
    return record


def _preflight(challenge: ChallengeSpec, input_dir: Path, files: list[dict[str, object]]) -> dict[str, object]:
    names = [str(item["path"]).casefold() for item in files]
    category = challenge.category
    dockerfiles = [name for name in names if name.endswith("dockerfile") or "/dockerfile" in name]
    compose = [name for name in names if name.endswith(("compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml"))]
    dependency_files = [name for name in names if name.endswith(("requirements.txt", "pyproject.toml", "package.json", "go.mod", "cargo.toml", "gemfile"))]
    text_sample = "\n".join(_small_text(path) for path in _regular_files(input_dir)[:100]) if input_dir.exists() else ""
    runtime: list[str] = []
    subtype = None
    if any(name.endswith(".py") for name in names): runtime.append("python")
    if "package.json" in names or any(name.endswith((".js", ".ts")) for name in names): runtime.append("node")
    if any("flask" in line.casefold() for line in text_sample.splitlines()): subtype = "Flask web application"
    elif "django" in text_sample.casefold(): subtype = "Django web application"
    elif "express" in text_sample.casefold(): subtype = "Express web application"
    elif category == "pwn" and any("elf" in str(item["kind"]).casefold() for item in files): subtype = "native ELF binary"
    elif category == "rev": subtype = "binary/static reverse engineering"
    elif category == "crypto": subtype = "cryptographic solver"
    surfaces = {
        "pwn": ["I/O protocol", "memory-corruption primitives", "mitigations and libc coupling"],
        "web": ["routes and authentication", "source-to-sink data flow", "container/dependency trust boundaries"],
        "rev": ["entry point and imports", "validation routine", "packing or anti-analysis"],
        "crypto": ["parameters and entropy", "input/output equations", "known weak construction families"],
        "forensic": ["file signatures and metadata", "embedded/recovered objects", "timeline and provenance"],
        "misc": ["file/protocol classification", "encoding layers", "runtime restrictions"],
        "cloud": ["identity and policy boundaries", "metadata/service endpoints", "deployment manifests"],
    }[category]
    hypotheses = [f"Inspect {surface} first" for surface in surfaces[:2]]
    tools = {
        "pwn": ["file", "readelf", "checksec", "gdb", "pwntools"],
        "web": ["rg", "curl", "python", "docker compose (only if required)"],
        "rev": ["strings", "objdump", "gdb", "radare2/ghidra on demand"],
        "crypto": ["python", "sympy", "pycryptodome", "z3 on demand"],
        "forensic": ["file", "exiftool", "binwalk", "tshark on demand"],
        "misc": ["file", "xxd", "python", "category-specific tools on demand"],
        "cloud": ["jq", "curl", "manifest-specific client on demand"],
    }[category]
    return {
        "docker": {"dockerfiles": dockerfiles, "compose_files": compose, "dependency_files": dependency_files},
        "runtime": sorted(set(runtime)), "subtype": subtype,
        "attack_surface": surfaces, "hypotheses": hypotheses, "recommended_tools": tools,
    }


def _small_text(path: Path) -> str:
    if path.stat().st_size > 512_000:
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="ignore")[:64_000]
    except OSError:
        return ""


def _readelf_value(output: str, key: str) -> str | None:
    for line in output.splitlines():
        if line.strip().startswith(f"{key}:"):
            return line.split(":", 1)[1].strip()
    return None


def _command_output(argv: list[str], *, limit: int = 16_000) -> str:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=10, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""
    return result.stdout[:limit].strip()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _make_read_only(root: Path) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        path.chmod(0o555 if path.is_dir() else 0o444)
    root.chmod(0o555)


def _remove_generated_tree(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_dir():
            path.chmod(0o755)
        else:
            path.chmod(0o644)
    root.chmod(0o755)
    shutil.rmtree(root)


def render_context(manifest: ContestManifest, record: dict[str, object]) -> str:
    challenge = f"{record['category']}/{record['name']}"
    lines = [f"# Context — {challenge}", "", f"- Number: {int(record['number']):02d}", f"- Stable ID: `{record['id']}`", f"- Status: **{record['status']}**", f"- Contest: {manifest.name}"]
    for label, key in (("Score", "score"), ("Description", "description"), ("Hint", "hint"), ("Flag format", "flag_format")):
        if record.get(key) is not None:
            lines.append(f"- {label}: {record[key]}")
    lines.extend(["", "## Authorized targets", ""])
    targets = record.get("authorized_targets") or []
    lines.extend(f"- `{target['declared']}`" for target in targets) if targets else lines.append("- None")
    lines.extend(["", "## Prepared evidence", "", f"- Input: `{record['prepared_input']}`", f"- Fingerprint: `{record.get('source_fingerprint')}`"])
    for item in record.get("files", []):
        details = item.get("elf")
        lines.append(f"- `{item['path']}` — {item['size']} bytes — `{item['sha256']}` — {item['kind']}" + (f" — ELF {details}" if details else ""))
    for heading, key in (("Initial attack surface", "attack_surface"), ("Initial hypotheses", "hypotheses"), ("Recommended tools", "recommended_tools"), ("Blockers", "blockers"), ("Solve session read paths", "read_paths")):
        lines.extend(["", f"## {heading}", ""])
        values = record.get(key) or []
        lines.extend(f"- {value}" for value in values) if values else lines.append("- None")
    return "\n".join(lines) + "\n"


def render_intake_markdown(payload: dict[str, object]) -> str:
    contest = payload["contest"]
    lines = [f"# {contest['name']} — Intake", ""]
    for record in payload["challenges"]:
        lines.extend([f"## [{int(record['number']):02d}] {record['status']} — {record['category']}/{record['name']}", ""])
        files = record.get("source_paths") or []
        targets = record.get("authorized_targets") or []
        lines.append(f"- Input: {', '.join(Path(path).name for path in files) if files else 'none'}")
        lines.append(f"- Remote: {', '.join(target['declared'] for target in targets) if targets else 'none'}")
        lines.append(f"- Estimated: {record.get('subtype') or record['category']}")
        direction = (record.get("hypotheses") or record.get("blockers") or ["none"])[0]
        lines.append(f"- Initial direction: {direction}")
        lines.append(f"- Solve selector: {int(record['number']):02d} or {record['category']}/{record['name']}")
        lines.append("")
    return "\n".join(lines)
