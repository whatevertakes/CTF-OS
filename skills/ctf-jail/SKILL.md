---
name: ctf-jail
description: Analyze sandbox, jail, blacklist, parser escape, and restricted execution challenges.
---

purpose: Analyze sandbox, jail, blacklist, parser escape, and restricted execution challenges.
when_to_use:
- The challenge constrains Python, shell, JavaScript, template engines, SQL, or another interpreter.
- A web or pwn chain produces a sandbox escape primitive.
when_not_to_use:
- The issue is standard injection without a meaningful execution restriction.
inputs:
- Jail source, blacklist/allowlist, interpreter version, prompt, and rejected payloads.
outputs:
- Constraint model, payload attempts, final bypass, and replayable proof.
dependencies:
- `skills/ctf-triage/SKILL.md`
- Optional Playwright MCP for browser-based sandboxes.
reference_digest:
- `docs/reference-digests/jail.md`
evidence produced:
- Payload log, error messages, accepted bypass, and final command output.
failure/blocker classes:
- Unknown interpreter version.
- Remote-only behavior without local reproduction.
- Challenge scope unclear.
future agent consumers:
- Jail solver.
- Web solver.
- Hybrid-chain solver.
workflow:
- Identify interpreter, version, blacklist, allowlist, parser, evaluation context, timeout, filesystem, and environment.
- Build a local reproducer when source or prompt behavior allows it.
- Log rejected payload families with exact errors; do not count simple spelling variants as new hypotheses.
- Explore encoding, object graph, import recovery, builtins recovery, parser confusion, template escape, shell escape, SQL escape, and browser escape families as applicable.
- Compare local and remote behavior before relying on a bypass.
- Preserve the final accepted payload and output transcript under `evidence/`.
first_commands:
- `python3 -V` or the relevant interpreter version command.
- `python3 work/reproduce_jail.py`
- `python3 work/payload_probe.py`
- `python3 tools/replay_runner.py <challenge-dir>`
pointers:
- `docs/CTF_SOLVE_PLAYBOOKS.md`
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
- `docs/LEVEL2_HYBRID_CHAINS.md`
