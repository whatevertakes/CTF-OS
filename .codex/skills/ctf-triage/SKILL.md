---
name: ctf-triage
description: "Run an optional legacy/admin whole-contest ranking from explicit Intake artifacts. Use only when the user explicitly says 'triage 해라', '추천 풀이 순서 정해라', '문제 우선순위 정해라', or explicitly requests a whole-contest ranking. This is a no-solve admin tool."
---

# Optional whole-contest Triage administration

This tool is not a Solve prerequisite, readiness source, or standard operating flow. Use it only for an explicit whole-contest administration request and only from explicit legacy Intake artifacts. Produce a bounded recommendation Board, not a solution or reconnaissance pass.

1. Read root `AGENTS.md`. Resolve the contest with `uv run python -m ctf_os.agent_tools inspect-contest --contest '<name>'` when the user named one. Omit `--contest` only when exactly one contest exists.
2. Run `uv run python -m ctf_os.agent_tools triage-prepare --contest '<name>'`.
3. Read only the returned `TRIAGE-CONTEXT.md`. It is a compact Python-produced summary of `contest.md`, `CONTEXT.md`, inventory, archive, authorized-target, and challenge metadata. Do not open the original challenge directory, `input/`, source code, binaries, full logs, or full inventories.
4. Keep Python's baseline Difficulty, Estimated solve time, Success probability, Setup cost, attack surface, sandbox, and playbook. Set only the final ordinal recommendation: `priority` with contiguous ranks starting at 1, `hold`, or `later`.

Base the order on the compact facts: estimated time, success probability, setup cost, surface clarity, ELF protections, input size, remote count, declared points, category/playbook, and special-tool requirements. Do not infer a vulnerability from a category alone. Treat absent evidence as `unknown`, not as easy or hard.

5. Give every READY challenge one assessment. Each assessment must cite 2–5 fact IDs that belong to that challenge. Send the compact JSON object directly:

```bash
uv run python -m ctf_os.agent_tools triage-finalize --contest '<name>' --assessments-json '{"assessments":[{"number":1,"recommendation":"priority","rank":1,"reason_fact_ids":["01.f1","01.f4"]},{"number":2,"recommendation":"hold","reason_fact_ids":["02.f2","02.f5"]}]}'
```

Do not supply a rank for `hold` or `later`. The finalizer rejects unsupported prose and fact IDs, then writes `output/<contest>/triage.json` and `TRIAGE.md`.

6. Read `TRIAGE.md` and show its READY/BLOCKED Board and recommended solve order. Mention both saved paths and stop. Do not direct the user into a replacement Solve session.

Keep this stage bounded to 1–2 minutes for a typical 8–20 challenge contest. Never use native delegation unless the supplied Board itself is too large to inspect in one pass; any helper may only rank a disjoint subset from the compact Board and must not access original files or perform solve actions.
