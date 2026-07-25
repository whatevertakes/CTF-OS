# CTF-OS Claude instructions

Follow [`AGENTS.md`](AGENTS.md). The authoritative runtime policy is
[`ctf_os/resources/agent-policy.md`](ctf_os/resources/agent-policy.md).

The repository audit prompt is preserved at
[`docs/prompts/repository-audit.md`](docs/prompts/repository-audit.md) and applies
only when an operator explicitly requests that audit.

The Claude Code-compatible terminal rescue skill is
`.claude/skills/ctf-claude-handoff/SKILL.md`. Load it immediately when the user
says “클로드 구조대 준비해라”.
