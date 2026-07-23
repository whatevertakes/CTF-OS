# CTF-OS repository audit

Audit the current repository. Do not redesign it, solve a challenge, edit files,
commit, push, or access external targets. Treat this as a hostile correctness and
security review of the tracked implementation.

## Contract

Read first, in order:

1. `AGENTS.md`
2. `ctf_os/resources/agent-policy.md`
3. `.codex/skills/ctf-solve/SKILL.md`
4. `README.md`, `pyproject.toml`, current source, and current tests

Use actual code paths and executable tests as truth. Inspect only files returned
by `git ls-files`. Never read, modify, delete, or summarize `incoming/`,
`output/`, `rescue/`, secrets, credentials, or untracked user files.

## Review targets

- `init-contest` safely creates only the requested fresh-schema contest and
  challenge input paths.
- `race-prepare` selects exactly one challenge, materializes read-only input,
  inspects and uses the local category image, creates the Root sandbox, and
  prepares only Root-owned service state without a second sandbox command.
- Root plus native children cannot exceed four; Python never starts, interrupts,
  or submits through a model/native-agent API.
- Worker packets are private, fresh context excludes unverified sibling history,
  and directed context includes only bounded receipt-backed blackboard deltas.
- Blackboard claims require completed execution receipts and preserve exact
  argv, exit code, bounded output, hashes, artifact identity, target, lane, and
  timestamp.
- Streaming flag detection accepts only the first non-placeholder pattern match
  from challenge/declared-target output, returns exact sibling cancel targets,
  and never waits for replay/reporting or auto-submits.
- Stagnation and duplicate fingerprints are mechanical and lane replacement
  preserves concurrency, sandbox privacy, and Root ownership.
- Input/path/symlink safety, declared-target egress, metadata/private-network
  blocking, credential isolation, Docker-socket isolation, service ownership,
  atomic state, timeout, handoff, and exact-run cleanup cannot be bypassed.
- Deleted legacy commands, modules, package data, dependencies, docs, and imports
  have no remaining runtime or packaging references.

## Verification

Run only repository-local, non-destructive checks:

```bash
git status --short
git diff --check
env -u CTF_OS_LIVE uv run pytest -q -m 'not live'
uv run python -m ctf_os.agent_tools --help
uv run python -m ctf_os.agent_tools init-contest --help
uv run python -m ctf_os.agent_tools race-prepare --help
```

Do not run live attacks, remote requests, image builds, pulls, or destructive
Docker cleanup. Report unavailable live Docker verification as untested.

## Output

Return only:

1. `VERDICT: PASS` or `VERDICT: FAIL`
2. Findings ordered `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`
3. For each finding: `file:line`, violated contract, concrete code/test evidence,
   impact, shortest reproducer, and minimal fix direction
4. Untested items caused by environment limits

Do not report style preferences, model opinions, speculative vulnerabilities,
internal reasoning, praise, or summaries without evidence. If no defect is found,
say `No findings` and list only untested items.
