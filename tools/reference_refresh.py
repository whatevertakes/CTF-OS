#!/usr/bin/env python3
"""Validate, lock, and materialize curated CTF references."""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import json
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - preflight requires PyYAML.
    yaml = None


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "references.yaml"
DEFAULT_LOCK = ROOT / "references.lock.json"
GITHUB_RE = re.compile(r"^https://github\.com/([^/]+)/([^/#?]+)(?:[/#?].*)?$")
ALLOWED_MODES = {"reference_digest", "optional_tool", "vendor", "local_implementation"}
REQUIRED_FIELDS = ("id", "category", "source_type", "url", "license", "mode", "why", "digest_path")


class FetchError(Exception):
    pass


def fail(message: str, code: int = 1) -> None:
    print(f"reference_refresh: {message}", file=sys.stderr)
    raise SystemExit(code)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST), help="reference manifest path")
    parser.add_argument("--lock", default=str(DEFAULT_LOCK), help="lock output path")
    parser.add_argument("--write-lock", action="store_true", help="write resolved metadata to references.lock.json")
    parser.add_argument("--refresh-lock", action="store_true", help="refresh lock metadata before materializing")
    parser.add_argument("--materialize", help="clone one GitHub reference id into its optional materialize path")
    parser.add_argument("--materialize-category", help="clone all GitHub references for one category")
    parser.add_argument("--materialize-all", action="store_true", help="clone all materializable GitHub references")
    parser.add_argument("--jobs", type=int, default=1, help="parallel clone jobs for materialization")
    return parser.parse_args()


def load_yaml(path: Path) -> dict[str, Any]:
    if yaml is None:
        fail("PyYAML is required", code=2)
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except OSError as exc:
        fail(f"cannot read manifest: {exc}", code=2)
    except yaml.YAMLError as exc:
        fail(f"invalid YAML: {exc}", code=2)
    if not isinstance(data, dict):
        fail("manifest root must be a mapping", code=2)
    return data


def as_categories(value: object, item_id: str) -> list[str]:
    if isinstance(value, str):
        categories = [value]
    elif isinstance(value, list) and all(isinstance(item, str) for item in value):
        categories = value
    else:
        fail(f"{item_id}: category must be a string or list of strings", code=2)
    normalized = [item.strip() for item in categories if item.strip()]
    if not normalized:
        fail(f"{item_id}: category must not be empty", code=2)
    return normalized


def validate_relative_template(value: str, field: str, item_id: str) -> None:
    path = Path(value.replace("{commit}", "commit"))
    if path.is_absolute() or ".." in path.parts:
        fail(f"{item_id}: {field} must be workspace-relative and non-escaping", code=2)


def validate_reference(raw: object, index: int) -> dict[str, Any]:
    if not isinstance(raw, dict):
        fail(f"reference {index}: must be a mapping", code=2)
    item_id = str(raw.get("id", f"reference-{index}"))
    missing = [field for field in REQUIRED_FIELDS if field not in raw]
    if missing:
        fail(f"{item_id}: missing required field(s): {', '.join(missing)}", code=2)
    for field in ("id", "source_type", "url", "license", "mode", "why", "digest_path"):
        if not isinstance(raw[field], str) or not raw[field].strip():
            fail(f"{item_id}: {field} must be a non-empty string", code=2)
    if raw["mode"] not in ALLOWED_MODES:
        fail(f"{item_id}: unsupported mode {raw['mode']!r}", code=2)
    validate_relative_template(str(raw["digest_path"]), "digest_path", item_id)
    materialize = raw.get("optional_materialize_path")
    if materialize is not None:
        if not isinstance(materialize, str) or not materialize.strip():
            fail(f"{item_id}: optional_materialize_path must be a non-empty string", code=2)
        validate_relative_template(materialize, "optional_materialize_path", item_id)
    source_subpath = raw.get("source_subpath")
    if source_subpath is not None:
        if not isinstance(source_subpath, str) or not source_subpath.strip():
            fail(f"{item_id}: source_subpath must be a non-empty string", code=2)
        path = Path(source_subpath)
        if path.is_absolute() or ".." in path.parts:
            fail(f"{item_id}: source_subpath must be repo-relative and non-escaping", code=2)
    return {**raw, "category": as_categories(raw["category"], item_id)}


def load_references(path: Path) -> list[dict[str, Any]]:
    data = load_yaml(path)
    if data.get("schema_version") != 1:
        fail("schema_version must be 1", code=2)
    refs = data.get("references")
    if not isinstance(refs, list):
        fail("manifest must contain references list", code=2)
    parsed = [validate_reference(raw, index) for index, raw in enumerate(refs, start=1)]
    ids = [item["id"] for item in parsed]
    duplicates = sorted({item_id for item_id in ids if ids.count(item_id) > 1})
    if duplicates:
        fail(f"duplicate reference id(s): {', '.join(duplicates)}", code=2)
    return parsed


def github_repo(url: str) -> tuple[str, str] | None:
    match = GITHUB_RE.match(url)
    if not match:
        return None
    owner = match.group(1)
    repo = match.group(2).removesuffix(".git")
    return owner, repo


def github_clone_url(ref: dict[str, Any]) -> str:
    repo = github_repo(str(ref["url"]))
    if repo is None:
        fail(f"reference is not a GitHub repository: {ref['id']}", code=2)
    owner, name = repo
    return f"https://github.com/{owner}/{name}"


def default_materialize_path(ref: dict[str, Any]) -> str:
    repo = github_repo(str(ref["url"]))
    if repo is None:
        return ""
    owner, name = repo
    safe = f"{owner}-{name}".replace(".", "-")
    return f".cache/references/{safe}@{{commit}}"


def fetch_json(url: str) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "ctf-workspace-reference-refresh"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        raise FetchError(f"network error fetching {url}: {exc}") from exc
    if not isinstance(data, dict):
        raise FetchError(f"unexpected JSON shape from {url}")
    return data


def git_head(repo_url: str) -> tuple[str, str]:
    result = subprocess.run(
        ["git", "ls-remote", "--symref", repo_url, "HEAD"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        return "", ""
    default_branch = ""
    commit = ""
    for line in result.stdout.splitlines():
        if line.startswith("ref: refs/heads/") and line.endswith("\tHEAD"):
            default_branch = line.removeprefix("ref: refs/heads/").removesuffix("\tHEAD")
        elif line.endswith("\tHEAD"):
            commit = line.split("\t", 1)[0]
    return default_branch, commit


def resolve_reference(ref: dict[str, Any]) -> dict[str, Any]:
    record: dict[str, Any] = {
        "id": ref["id"],
        "url": ref["url"],
        "category": ref["category"],
        "source_type": ref["source_type"],
        "mode": ref["mode"],
        "digest_path": ref["digest_path"],
        "resolved_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    if isinstance(ref.get("source_subpath"), str):
        record["source_subpath"] = ref["source_subpath"]
    repo = github_repo(ref["url"])
    if repo is None:
        record["resolution"] = "non_github_reference"
        return record
    owner, name = repo
    repo_url = f"https://github.com/{owner}/{name}"
    api = f"https://api.github.com/repos/{owner}/{name}"
    try:
        meta = fetch_json(api)
    except FetchError as exc:
        default_branch, commit = git_head(repo_url)
        record.update(
            {
                "resolution": "github_partial",
                "full_name": f"{owner}/{name}",
                "default_branch": default_branch,
                "commit": commit,
                "resolution_error": str(exc),
            }
        )
        return record
    default_branch = str(meta.get("default_branch") or "")
    license_info = meta.get("license")
    record.update(
        {
            "resolution": "github",
            "full_name": meta.get("full_name", f"{owner}/{name}"),
            "default_branch": default_branch,
            "updated_at": meta.get("updated_at", ""),
            "license": license_info.get("spdx_id") if isinstance(license_info, dict) else "",
        }
    )
    if default_branch:
        try:
            branch = fetch_json(f"{api}/branches/{default_branch}")
        except FetchError as exc:
            _, commit_sha = git_head(repo_url)
            record["commit"] = commit_sha
            record["resolution_error"] = str(exc)
        else:
            commit = branch.get("commit")
            if isinstance(commit, dict):
                record["commit"] = commit.get("sha", "")
    return record


def load_lock(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read lock: {exc}", code=2)
    refs = data.get("references") if isinstance(data, dict) else None
    if not isinstance(refs, list):
        fail("lock must contain references list", code=2)
    return [item for item in refs if isinstance(item, dict) and isinstance(item.get("id"), str)]


def merge_records(old_records: list[dict[str, Any]], new_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    old_by_id = {str(item["id"]): item for item in old_records}
    merged: list[dict[str, Any]] = []
    for record in new_records:
        old = old_by_id.get(str(record["id"]), {})
        kept = {
            key: old[key]
            for key in ("materialized_path", "materialized_at", "materialized_commit")
            if key in old
        }
        merged.append({**record, **kept})
    return merged


def write_lock(path: Path, records: list[dict[str, Any]]) -> None:
    lock = {
        "schema_version": 1,
        "generated_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "references": records,
    }
    path.write_text(json.dumps(lock, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def git_rev_parse(path: Path) -> str:
    result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=path, text=True, capture_output=True, check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


def ensure_target_inside_cache(target: Path) -> None:
    try:
        target.resolve().relative_to((ROOT / ".cache" / "references").resolve())
    except ValueError:
        fail(f"materialize target must stay under .cache/references: {target}", code=2)


def clone_reference(ref: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    commit = str(record.get("commit") or "")
    if not commit:
        raise RuntimeError(f"cannot materialize without resolved commit: {ref['id']}")
    target_template = ref.get("optional_materialize_path") or default_materialize_path(ref)
    if not isinstance(target_template, str) or "{commit}" not in target_template:
        raise RuntimeError(f"reference lacks optional_materialize_path with {{commit}}: {ref['id']}")
    target = ROOT / target_template.replace("{commit}", commit[:12])
    ensure_target_inside_cache(target)
    if target.exists():
        current = git_rev_parse(target)
        if current != commit:
            raise RuntimeError(f"{target.relative_to(ROOT)} has commit {current or 'unknown'}, expected {commit}")
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        clone_url = github_clone_url(ref)
        result = subprocess.run(
            ["git", "clone", "--filter=blob:none", "--single-branch", "--depth", "1", clone_url, target.as_posix()],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            if target.exists():
                shutil.rmtree(target)
            result = subprocess.run(
                ["git", "clone", "--filter=blob:none", clone_url, target.as_posix()],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or f"git clone failed for {ref['id']}")
        checkout = subprocess.run(["git", "checkout", commit], cwd=target, text=True, capture_output=True, check=False)
        if checkout.returncode != 0:
            shutil.rmtree(target)
            result = subprocess.run(
                ["git", "clone", "--filter=blob:none", clone_url, target.as_posix()],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip() or f"git clone failed for {ref['id']}")
            checkout = subprocess.run(["git", "checkout", commit], cwd=target, text=True, capture_output=True, check=False)
            if checkout.returncode != 0:
                raise RuntimeError(checkout.stderr.strip() or f"git checkout failed for {ref['id']}")
    return {
        **record,
        "materialized_path": target.relative_to(ROOT).as_posix(),
        "materialized_commit": commit,
        "materialized_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }


def select_refs(refs: list[dict[str, Any]], args: argparse.Namespace) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    if args.materialize:
        selected.extend([ref for ref in refs if ref["id"] == args.materialize])
    if args.materialize_category:
        category = args.materialize_category.strip()
        selected.extend([ref for ref in refs if category in ref["category"] and github_repo(str(ref["url"])) is not None])
    if args.materialize_all:
        selected.extend([ref for ref in refs if github_repo(str(ref["url"])) is not None])
    unique: dict[str, dict[str, Any]] = {}
    for ref in selected:
        unique[str(ref["id"])] = ref
    if args.materialize and args.materialize not in unique:
        fail(f"unknown or non-materializable reference id: {args.materialize}", code=2)
    return list(unique.values())


def materialize_many(refs: list[dict[str, Any]], records: list[dict[str, Any]], jobs: int) -> list[dict[str, Any]]:
    by_id = {str(record["id"]): record for record in records}
    updated = dict(by_id)
    work = [(ref, by_id.get(str(ref["id"]), {})) for ref in refs]
    if not work:
        return records

    def run_one(item: tuple[dict[str, Any], dict[str, Any]]) -> tuple[str, dict[str, Any]]:
        ref, record = item
        if not record:
            raise RuntimeError(f"missing lock record for {ref['id']}")
        materialized = clone_reference(ref, record)
        return str(ref["id"]), materialized

    if jobs <= 1:
        for item in work:
            item_id, materialized = run_one(item)
            print(materialized["materialized_path"])
            updated[item_id] = materialized
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as executor:
            futures = [executor.submit(run_one, item) for item in work]
            for future in concurrent.futures.as_completed(futures):
                item_id, materialized = future.result()
                print(materialized["materialized_path"])
                updated[item_id] = materialized
    return [updated.get(str(record["id"]), record) for record in records]


def main() -> int:
    args = parse_args()
    manifest = Path(args.manifest).expanduser()
    if not manifest.is_absolute():
        manifest = ROOT / manifest
    lock = Path(args.lock).expanduser()
    if not lock.is_absolute():
        lock = ROOT / lock

    refs = load_references(manifest.resolve())
    selected = select_refs(refs, args)
    old_records = load_lock(lock.resolve())
    should_resolve = args.write_lock or args.refresh_lock or not old_records
    if should_resolve:
        records = merge_records(old_records, [resolve_reference(ref) for ref in refs])
    else:
        records = old_records
    if selected:
        records = materialize_many(selected, records, max(1, args.jobs))
        write_lock(lock.resolve(), records)
    elif args.write_lock or args.refresh_lock:
        write_lock(lock.resolve(), records)
    print(f"reference_refresh ok: references={len(refs)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
