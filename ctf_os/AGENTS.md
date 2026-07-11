# CTF-OS Agent Instructions

This repository implements CTF-OS, a local-first multi-node CTF agent.

## Operating Model

- No central executor.
- No remote worker stealing.
- No shared Codex account.
- No CTFd auto-submit.
- Each member runs a local node on their own PC.
- TeamSync only shares append-only JSONL events for status, findings, and flags.
- Challenge commands must run through per-attempt Docker containers whenever possible.

## Model Routing

Use GPT-5.6 roles deliberately:

- Sol (`gpt-5.6-sol`): architecture, supervision, difficult strategy, final verification.
- Terra (`gpt-5.6-terra`): normal implementation, exploit scripts, feature work.
- Luna (`gpt-5.6-luna`): recon, summarization, cheap parallel attempts, log reduction.

The default Codex model for repository work is Sol. Implementation code should still make model routing configurable and include fallbacks.

## Safety

- Authorized CTF challenges only.
- Only connect to remotes explicitly listed in `incoming/{contest}/contest.md`.
- Do not scan unrelated networks.
- Do not access credentials, SSH keys, browser data, API keys, or personal files.
- Do not modify host system configuration from solver workers.
- Do not write outside `/work` and `/artifacts` from solver workers.
- Do not invent flags or print placeholder flags as real results.

## Engineering

- Prefer `uv` for Python commands.
- Keep MVP modules small and testable.
- Use SQLite for local state and JSONL for append-only events.
- Keep Docker cleanup label-based and scoped to the local member/team/challenge.
- Add focused pytest coverage for parser, state, events, model routing, sandbox command construction, and mock worker flows.

