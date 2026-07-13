---
name: ctf-triage
description: "Create an evidence-backed recommended solve order for every challenge in an authorized CTF contest after Intake. Use when the user says 'triage 해라', '추천 풀이 순서 정해라', '문제 우선순위 정해라', or asks to rank/select CTF challenges before solving. This is a no-solve stage: use only Intake artifacts and never open challenge input, start a sandbox/service, contact a remote, exploit, brute force, fuzz, symbolically execute, or run a solver."
---

# CTF Challenge Triage

Act in a new dedicated Sol session after Intake. Produce a quick recommendation Board, not a solution or a reconnaissance pass.

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

6. Read `TRIAGE.md` and show its READY/BLOCKED Board and recommended solve order. Mention both saved paths. Stop there; let the human start a new Sol session and choose a selector such as `1번 문제 풀어`.

Keep this stage bounded to 1–2 minutes for a typical 8–20 challenge contest. Never use native delegation unless the supplied Board itself is too large to inspect in one pass; any helper may only rank a disjoint subset from the compact Board and must not access original files or perform solve actions.
