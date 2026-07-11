# CTF-OS Agent Instructions

This repository implements CTF-OS, a local-first multi-node CTF agent.

## Operating model

- No central executor, remote worker stealing, shared Codex account, or CTFd auto-submit.
- Each member runs a local node on their own PC.
- TeamSync shares only append-only JSONL events for status, findings, and flags.
- Challenge commands run through per-attempt Docker containers whenever possible.

## Model routing

- Sol (`gpt-5.6-sol`): architecture, supervision, strategy, final verification.
- Terra (`gpt-5.6-terra`): implementation and normal solver work.
- Luna (`gpt-5.6-luna`): recon, summarization, and cheap parallel attempts.

## Safety

- Work only on authorized CTF challenges and remotes declared in `incoming/{contest}/contest.md`.
- Never access credentials, personal files, unrelated networks, or host configuration from solver workers.
- Workers write only to `/work` and `/artifacts`.
- Do not invent flags or publish placeholders as real findings.

## Engineering

- Prefer `uv`; retain SQLite local state and TeamSync JSONL history.
- Keep Docker cleanup label-scoped to the local member/team/challenge.
- Add focused tests for parser, state, events, sandbox, model routing, and mock worker flows.
