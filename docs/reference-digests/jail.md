# Jail Reference Digest

## Trusted Sources

- `ref:upstream_ctf_skills`: misc subskills for pyjails and bashjails.
- `ref:tplmap`: template sandbox and SSTI escape reference when the jail is template-backed.
- `ref:owasp_cheatsheets`: injection and sandbox-adjacent guidance.

## CTF-Relevant Patterns

- Identify interpreter, version, blacklist, allowlist, parser, evaluation context, timeout, builtins, imports, filesystem, and environment.
- Build a local reproducer when source or prompt behavior allows it.
- Group payloads by bypass family: encoding, object graph, parser confusion, import recovery, builtins recovery, shell escape, template escape, SQL escape, browser escape, or syscall surface.
- Compare local and remote behavior before trusting a payload.

## CWE/CVE Mapping

- Map sandbox escape, command injection, template injection, or deserialization only after accepted payload behavior is evidenced.
- CVEs are relevant only for known interpreter/framework versions or sandbox libraries.

## Canonical Papers And Deep Dives

- Python object graph escape, shell parsing, JavaScript sandbox, and template-engine escape notes are useful pattern references.

## When To Use

- Use for restricted interpreters, parser escapes, shell/Python/JS/template jails, and sandbox bypass tasks.

## When Not To Use

- Do not use for ordinary injection without a meaningful execution restriction.

## Source Anchors

- `idx:jail:upstream_ctf_skills:overview`
- `idx:jail:tplmap:overview`
- `idx:jail:owasp_cheatsheets:overview`
