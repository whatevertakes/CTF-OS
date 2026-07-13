# Sol-native refactor deletion record

This worktree was clean before the refactor. Ignored user data exists below
`incoming/` and `output/`; those trees are preserved and are never bulk-cleaned.

## Replace

- Config-bound contest parsing and intake: replace with a `contest.md`-only contract.
- Team/member sandbox scope: replace with contest/challenge/branch scope.
- SQLite/lease evidence and result state: replace with challenge-local JSON/Markdown/log files.
- Codex-backed solving: replace with repository skills for the already-open Sol session.

## Delete

- Python application, CLI, config, scheduler, watcher, worker, state and TUI layers.
- `solver_engine`, `tactical_engine`, Codex subprocess backend and broker transport.
- Team deployment, benchmark, release/self-test and profile infrastructure.
- User YAML/model-routing configuration and duplicated packaged Docker resources.
- Legacy docs/tests and duplicated top-level knowledge tree.

## Keep in reduced form

- Category canonicalization, stable challenge identity, safe archive extraction.
- Intake reconnaissance, challenge workspace preparation, evidence and flag verification.
- One Dockerfile/entrypoint plus an argv-only sandbox lifecycle.
- Curated category playbooks and native-agent role policy.
