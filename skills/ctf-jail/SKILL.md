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
pointers:
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
- `docs/LEVEL2_HYBRID_CHAINS.md`
