purpose: Analyze AI/ML security CTF tasks involving prompt injection, model behavior, agents, classifiers, or ML artifacts.
when_to_use:
- The challenge centers on prompts, model outputs, model files, embedding/search behavior, or agent tool use.
when_not_to_use:
- Solving requires storing real API secrets or targeting systems outside the challenge scope.
inputs:
- Prompt transcript, model instructions, tool logs, model artifacts, datasets, or web-agent output.
outputs:
- Reproducible prompt or model test, extracted behavior, payload, and downstream routing.
dependencies:
- `skills/ctf-triage/SKILL.md`
- garak and Damn Vulnerable LLM Agent references only.
evidence produced:
- Prompt logs, model outputs, sanitized tool traces, and replay notes.
failure/blocker classes:
- Missing model or prompt context.
- Secrets required for reproduction.
- Non-deterministic output without enough samples.
future agent consumers:
- AI/ML solver.
- Web solver.
- Hybrid-chain solver.
pointers:
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
- `docs/LEVEL2_IMPORT_POLICY.md`
- `docs/LEVEL2_HYBRID_CHAINS.md`
