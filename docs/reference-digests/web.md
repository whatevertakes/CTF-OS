# Web Reference Digest

## Trusted Sources

- `ref:upstream_ctf_skills`: web subskills for auth, JWT, SQLi, server-side execution, deserialization, Node, and CVEs.
- `ref:owasp_wstg`: web testing methodology reference.
- `ref:owasp_cheatsheets`: weakness-specific web guidance.
- `ref:owasp_top10`: official web risk taxonomy for classifying findings.
- `ref:owasp_api_security`: API-specific authz, object, function, and inventory risk reference.
- `ref:portswigger_wsa`: local Web Security Academy snapshot for common exploit methodologies.
- `ref:sqlmap`: SQL injection oracle and payload reference.
- `ref:tplmap`: SSTI reference.
- `ref:hacktricks`: broad offensive web checklist reference.
- `ref:payloads_all_the_things`: payload and bypass reference for evidence-backed branches.

## CTF-Relevant Patterns

- Freeze URL, source, roles, cookies, CSRF, routes, methods, content types, and state-changing endpoints before payload work.
- Branch auth/session, source disclosure, policy oracle, mutation, render/runtime, upload/archive, SSRF/internal, and client-side behavior separately.
- Record request/response pairs and mutation ledger rows; do not count encoding variants as new hypotheses.
- Use scanners only after a concrete endpoint, parameter, parser, or version is evidenced.
- Use PortSwigger pages for methodology when evidence names SQLi, XSS, SSTI,
  traversal, XXE, SSRF, auth, JWT, OAuth, upload, deserialization, prototype
  pollution, request smuggling, race, or cache behavior.
- Use PayloadsAllTheThings only after the sink or parser family is known; record
  the exact payload family and negative variants.

## CWE/CVE Mapping

- Map injection to CWE-89/CWE-94/CWE-1336/CWE-78 only after sink behavior is observed.
- Map traversal/disclosure to CWE-22/CWE-200 only with path or response evidence.
- Match CVEs only when product/version/commit evidence exists.

## Canonical Papers And Deep Dives

- OWASP Top 10, WSTG, and Cheat Sheet Series for vulnerability classes and testing methodology.
- PortSwigger Web Security Academy labs are useful pattern references when local behavior matches.

## When To Use

- Use for web apps, APIs, browser challenges, SSRF, uploads, renderers, auth/session, and server-side template or deserialization behavior.

## When Not To Use

- Do not use for a leaked binary, standalone crypto primitive, or memory image after the web boundary artifact has been preserved.

## Source Anchors

- `idx:web:upstream_ctf_skills:overview`
- `idx:web:owasp_wstg:overview`
- `idx:web:owasp_cheatsheets:overview`
- `idx:web:owasp_top10:overview`
- `idx:web:owasp_api_security:overview`
- `idx:web:portswigger_wsa:overview`
- `idx:web:sqlmap:overview`
- `idx:web:tplmap:overview`
- `idx:web:hacktricks:overview`
- `idx:web:payloads_all_the_things:overview`
