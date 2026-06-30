# AI/ML Reference Digest

## Trusted Sources

- `ref:garak`: LLM vulnerability scanner reference.
- `ref:damn_vulnerable_llm_agent`: agentic LLM security training reference.
- `ref:promptfoo`: prompt and model evaluation reference.
- `ref:owasp_cheatsheets`: AI and prompt-security-adjacent guidance.

## CTF-Relevant Patterns

- Freeze prompts, hidden instructions, tool descriptions, retrieval context, datasets, model artifacts, transcripts, and non-determinism settings.
- Never store real API keys or credentials.
- Test prompt injection, instruction hierarchy, classifier behavior, embedding retrieval, tool use, and downstream web/API effects with transcripts.
- Sample nondeterministic behavior enough to separate signal from noise.

## CWE/CVE Mapping

- CVEs usually apply only to specific model-serving software, plugins, vector DBs, or web components with version evidence.
- Map prompt injection and tool misuse as behavior classes rather than direct CVE claims unless a product advisory exists.

## Canonical Papers And Deep Dives

- Prompt injection, indirect prompt injection, tool-use exploitation, and retrieval poisoning papers are relevant when the task exposes those channels.

## When To Use

- Use for prompts, model outputs, embedding/search behavior, classifier behavior, agent tools, and LLM-driven web/API effects.

## When Not To Use

- Do not use if reproduction requires storing real secrets or targeting non-challenge systems.

## Source Anchors

- `idx:ai-ml:garak:overview`
- `idx:ai-ml:damn_vulnerable_llm_agent:overview`
- `idx:ai-ml:promptfoo:overview`
- `idx:ai-ml:owasp_cheatsheets:overview`
