# CTF-OS — Sol-native operating contract

CTF-OS is a support toolkit for the Sol session the user opened in this repository. The current Sol session is the orchestrator. Python provides parsing, safe file preparation, sandboxing, evidence, and flag verification only; it must never start Codex or own the reasoning loop.

## User manifest and scope

- `incoming/<contest>/problems.txt` is the only user-maintained contest input. `contest.md` is an internal manifest generated from it by Intake.
- Work only on challenge files under that contest and remotes explicitly declared there.
- Never access credentials, SSH keys, browser data, personal files, host configuration, or unrelated networks.
- Never automate CTFd login or flag submission. Give a verified candidate to the human.

## Intake request

For “intake 해라”, “대회 문제 읽어라”, “문제 목록 준비해라”, or a named contest intake request, load `.codex/skills/ctf-intake/SKILL.md`. Intake is a dedicated session: inspect all challenges, generate `output/<contest>/intake.json` and `INTAKE.md`, print the numbered status list, then stop. Fast bounded triage is allowed; do not start the solve race.

## Solve request

For “N번 문제 풀어라”, `category/name`, a challenge name, deep solve, or swarm requests, load `.codex/skills/ctf-solve/SKILL.md`. Solve exactly one challenge in a new session. Resolve `1`, `01`, `1번`, exact category/name, or unambiguous name through the internal tool. Never guess an ambiguous challenge or contest.

## Native swarm

Use Codex runtime native delegation, never shell/subprocess model launchers or broker protocols. Sol selects Tier 0–4 from evidence: 0 children for trivial work, at most 1 for easy, 2 for normal, 3 for hard, and 4 only after a genuine multi-family stall. Start with 1–2 non-overlapping branches by default and expand only for a distinct attack family, independent verification, parallel implementation, isolated long tool, plateau, or high-value alternate hypothesis. Sol compares compact findings, ends weak branches, and takes over stalled high-value work. Use Luna/Terra/Sol role guidance when exact model selection is available; otherwise separate roles without claiming pinning.

## Sandbox and evidence

Invoke internal JSON tools with `uv run python -m ctf_os.agent_tools ...`. Challenge input is read-only at `/challenge`; only attempt-private `/work` and `/artifacts` are writable. Use one resource-admitted sandbox per branch, declared remotes or the challenge's internal service network only, bounded time/resources, explicit artifact export, and always clean up. Record raw command output in locked `evidence.log`; append supported, rejected, and inconclusive hypotheses to locked `FINDINGS.md`/`findings.jsonl`. Workers return only the compact report schema from the solve skill.

Do not mark a problem solved from a flag-looking string. Use structured `REPRODUCE.json` and the sandbox-native `replay` tool. Require the current fingerprint, solver artifact, two distinct clean local receipts, flag-pattern match, and an authorized remote receipt with actual network observation when a remote exists. Only then use `READY_FOR_HUMAN_SUBMISSION`; submission remains manual.
