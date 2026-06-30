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
reference_digest:
- `docs/reference-digests/ai-ml.md`
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
workflow:
- Freeze prompts, hidden instructions, tool descriptions, datasets, model artifacts, transcripts, retrieval context, and non-determinism settings.
- Never store real API secrets or credentials in challenge files.
- Test prompt injection, instruction hierarchy, classifier behavior, embedding retrieval, agent tools, and downstream browser/API effects with transcripts.
- Sample nondeterministic outputs enough to separate signal from noise.
- Route concrete web/API/tool effects to the matching category only when evidenced.
first_commands:
- Save prompt/input and model output samples under `evidence/`.
- `python3 work/replay_prompt.py`
- `python3 work/analyze_outputs.py`
- `python3 tools/proof_validate.py <challenge-dir>`
pointers:
- `docs/CTF_SOLVE_PLAYBOOKS.md`
- `docs/LEVEL2_CATEGORY_COVERAGE.md`
- `docs/LEVEL2_IMPORT_POLICY.md`
- `docs/LEVEL2_HYBRID_CHAINS.md`
