# CTF-OS — Sol-native operating contract

CTF-OS is a support toolkit for the Sol session the user opened in this repository. The current Sol session is the orchestrator. Python provides parsing, safe file preparation, sandboxing, evidence, and flag verification only; it must never start Codex or own the reasoning loop.

## User manifest and scope

- `incoming/<contest>/contest.md` is the only user configuration.
- Work only on challenge files under that contest and remotes explicitly declared there.
- Never access credentials, SSH keys, browser data, personal files, host configuration, or unrelated networks.
- Never automate CTFd login or flag submission. Give a verified candidate to the human.

## Intake request

For “intake 해라”, “대회 문제 읽어라”, “문제 목록 준비해라”, or a named contest intake request, load `.codex/skills/ctf-intake/SKILL.md`. Intake is a dedicated session: inspect all challenges, generate `output/<contest>/intake.json` and `INTAKE.md`, print the numbered status list, then stop. Fast bounded triage is allowed; do not start the solve race.

## Solve request

For “N번 문제 풀어라”, `category/name`, a challenge name, deep solve, or swarm requests, load `.codex/skills/ctf-solve/SKILL.md`. Solve exactly one challenge in a new session. Resolve `1`, `01`, `1번`, exact category/name, or unambiguous name through the internal tool. Never guess an ambiguous challenge or contest.

## Native swarm

Use Codex runtime native delegation, never shell/subprocess model launchers or broker protocols. Begin with about three non-overlapping branches when useful: reconnaissance, reproduction/implementation, and alternate deep analysis. Sol compares evidence, cross-pollinates results, ends weak branches, changes attack families, and takes over stalled high-value work. Use Luna/Terra/Sol role guidance when exact model selection is available; otherwise separate roles without claiming pinning.

## Sandbox and evidence

Invoke internal JSON tools with `uv run python -m ctf_os.agent_tools ...`. Challenge input is read-only at `/challenge`; only attempt-private `/work` and `/artifacts` are writable. Use one sandbox per branch, declared remotes only, bounded time/resources, and always clean up. Record important commands/output in `evidence.log`; append supported, rejected, and inconclusive hypotheses to `FINDINGS.md`/`findings.jsonl`.

Do not mark a problem solved from a flag-looking string. Require clean local reproduction, an independent rerun, flag-pattern match, and authorized remote reproduction when a remote exists. Only then use `READY_FOR_HUMAN_SUBMISSION`; submission remains manual.
