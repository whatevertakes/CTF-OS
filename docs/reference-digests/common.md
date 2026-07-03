# Common Reference Digest

## Trusted Sources

- `ref:upstream_ctf_skills`: CTF agent skill category source material.
- `ref:cve_mitre`: CVE identifier and record authority.
- `ref:nvd_nist`: CVE enrichment, CVSS, CPE, and CWE mapping.
- `ref:cisa_kev`: known exploited vulnerability signal.
- `ref:mitre_cwe_top25`: weakness taxonomy and common bug-class vocabulary.
- `ref:cisa_kev_json`: local KEV JSON snapshot for exact CVE/product/date matching.
- `ref:cve_json_schema`: official CVE JSON record schema for interpreting CVE-shaped data.

## CTF-Relevant Patterns

- Treat references as hypothesis and routing aids, not as proof.
- Prefer local artifact evidence before matching a known CVE or tool recipe.
- Separate vulnerability class, exploit primitive, proof scope, and remote status.
- Record negative results when a known pattern does not fit the local target.

## CWE/CVE Mapping

- Use CWE names to normalize observations such as injection, memory corruption, path traversal, authz bypass, deserialization, and cryptographic misuse.
- Use CVE/NVD/CISA only after a product, version, commit, library, or behavior is evidenced locally.
- Query the local KEV snapshot when challenge evidence names a product, version,
  CVE id, vendor, or exploited-in-the-wild clue.
- Use the CVE JSON schema when parsing downloaded CVE records or normalizing
  CVE references from challenge handouts.
- Do not escalate severity from CVE reputation alone; CTF proof still requires challenge-local replay evidence.

## Canonical Papers And Deep Dives

- ReAct and SWE-agent style act/observe loops support explicit action, observation, and verification traces.
- Harness-engineering guidance supports durable local memory, validation scripts, and bounded workers.
- Category-specific deep dives live in the per-category digest files.

## When To Use

- Use before Level3 planning, category routing, tool selection, or CVE matching.
- Use when a worker needs a normalized vulnerability vocabulary.

## When Not To Use

- Do not use as a substitute for `state.json`, `notes.md`, replay logs, or proof validation.
- Do not use to justify scanning or exploitation outside the challenge scope.

## Source Anchors

- `idx:common:upstream_ctf_skills:overview`
- `idx:common:cve_mitre:overview`
- `idx:common:nvd_nist:overview`
- `idx:common:cisa_kev:overview`
- `idx:common:mitre_cwe_top25:overview`
- `idx:common:cisa_kev_json:cisa-kev-json`
- `idx:common:cve_json_schema:overview`
