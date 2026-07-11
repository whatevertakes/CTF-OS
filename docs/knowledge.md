# Local knowledge seed

`knowledge/` is a local-only CTF reference seed. It contains generic methodology and tool notes for authorized challenges; it contains no target endpoints, credentials, or challenge flags.

Refresh an index in a workspace with:

```bash
ctf-os knowledge index
ctf-os knowledge query --category web --text "template error" --finding "template expression reflected"
```

## Pinned external references

CTF-OS includes a reviewed, local snapshot of selected reference Markdown from
[ljagiello/ctf-skills](https://github.com/ljagiello/ctf-skills), commit
`0a3a9c41bdef1ffb845e71cb53a7a6adbec85956`. It is used under the MIT License;
the complete upstream license and attribution notice are retained at
`knowledge/external/ctf-skills/LICENSE` and `NOTICE.md` (and in the packaged
resource mirror).

The packaged default contains only reference `.md` files from `ctf-pwn`,
`ctf-web`, `ctf-reverse`, `ctf-crypto`, `ctf-forensics`, and `ctf-misc`.
It excludes `SKILL.md`, repository guidance, scripts, tests, GitHub metadata,
writeup/orchestration material, and the `malware`, `osint`, and `ai-ml`
families. The latter families are opt-in only and are never packaged by the
default snapshot.

To reproduce the source snapshot from an already-local checkout (no clone or
network access occurs):

```bash
ctf-os knowledge import /path/to/ctf-skills \
  --commit 0a3a9c41bdef1ffb845e71cb53a7a6adbec85956
ctf-os knowledge audit --json
```

`import` uses directory-descriptor, no-follow reads and atomically replaces
only `external/ctf-skills`. A Git `HEAD` at the pin is necessary but not
sufficient: every selected default-family file and its section metadata must
match the release-reviewed canonical manifest. That package resource is itself
bound by a SHA-256 digest fixed in code, so an edited checkout or snapshot
cannot authorize its own provenance. Symlinks, path escapes, NUL bytes, invalid
UTF-8, oversized input, generated files, missing files, and extra files are
blocked. It never executes fenced commands or fetches links. Use
`--dry-run --json` to inspect an import. `malware`, `osint`, and `ai-ml` are
rejected until a canonical review and pinned hash set are shipped for them.

Sections are classified as `accepted`, `reviewed`, `quarantined`, or `skipped`.
Prompt-control content is quarantined. Remote-scanning, credential/private-key,
browser, cloud-metadata, and privilege-related sections are reviewed. Retrieval
uses accepted content only by default; operators must explicitly pass
`--include-reviewed` or `--trust reviewed` to retrieve reviewed material.
Each JSONL/SQLite chunk records trust, provenance, flags, truncation, and link
metadata. Links remain local metadata only; they are never fetched.

Both commands use only local files. `audit` requires the snapshot's complete
regular-file set to be exactly `manifest.json`, `LICENSE`, `NOTICE.md`, and the
canonical manifest registrations. If that check or any manifest/hash/section
check fails, indexing quarantines the whole `external/ctf-skills` subtree: it
is never treated as local accepted knowledge. The index command writes
`knowledge/indexes/knowledge.sqlite` and `knowledge/indexes/chunks.jsonl`
using a temporary file and atomic replace for each individual file. The two
replacements are not one crash-atomic transaction; after an interruption,
rerun `ctf-os knowledge index` to regenerate the matching pair. Indexing
ignores symlinks, files outside the root, binary content, oversized files, and
its own generated `indexes/` directory.

The wheel contains a byte-for-byte mirror under `ctf_os.resources/knowledge`. When `./knowledge` does not exist, the CLI creates that local copy before indexing, so installed copies do not need to write into package directories. Keep user writeups below `knowledge/writeups/<category>/`; generated indexes are intentionally not source content.
