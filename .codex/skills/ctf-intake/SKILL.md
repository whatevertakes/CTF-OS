---
name: ctf-intake
description: Run an optional legacy/admin whole-contest inventory. Use only when the user explicitly says "intake 해라", "대회 문제 읽어라", "문제 목록 준비해라", or explicitly requests a named whole-contest inventory.
---

# Optional whole-contest Intake administration

This tool is not a Solve prerequisite or readiness source. Run it only for an explicit whole-contest administration request. Do not begin a full exploit race and never launch another Codex process.

1. Read root `AGENTS.md` and identify the requested contest. Treat only remotes declared in its `contest.md` as authorized.
2. Run `uv run python -m ctf_os.agent_tools inspect-contest --contest '<name>'` when a contest is named. Omit `--contest` only when exactly one contest exists. If selection is ambiguous, show the returned candidates; do not guess.
3. Run `uv run python -m ctf_os.agent_tools intake --contest '<name>'`. This safely materializes and inspects every challenge independently, then writes `output/<contest>/intake.json`, `INTAKE.md`, and each `CONTEXT.md`.
4. Review every BLOCKED record and its actionable reason. A damaged archive for one challenge must not hide READY siblings.
5. Check the generated context for hashes, MIME/kind, ELF metadata, Docker/Compose/dependencies, runtimes, attack surface, hypotheses, tools, authorized targets, and solve read paths.

For unusually broad inputs, use native delegation for at most 1–3 bounded, read-only triage tasks. Give each branch distinct files or categories and ask it to return evidence only. Model pinning is optional: use Sol/Terra/Luna roles when the runtime supports exact selection; otherwise use available native agents and state that the model was not pinned. Never use subprocesses, sockets, stdout protocols, or Python code to create model workers.

Finish with the numbered list from `INTAKE.md`, including status, category/name, inputs, remote, estimate, initial direction, and selector. State the two saved index paths and stop. Do not direct the user through Triage or a replacement Solve session.
