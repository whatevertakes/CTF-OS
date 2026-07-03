# Category Reference Map

Level 2 uses curated references as compressed category memory. References are
not loaded by default and are not proof. Workers read the category skill,
`docs/CTF_SOLVE_PLAYBOOKS.md`, the relevant digest, and the relevant
`docs/reference-index/*.json` before probing.

| Category | Digest | Primary references |
|---|---|---|
| common | `docs/reference-digests/common.md` | `upstream_ctf_skills`, `cve_mitre`, `nvd_nist`, `cisa_kev`, `mitre_cwe_top25`, `cisa_kev_json`, `cve_json_schema` |
| pwn | `docs/reference-digests/pwn.md` | `upstream_ctf_skills`, `pwntools`, `pwndbg`, `how2heap`, `ropgadget` |
| web | `docs/reference-digests/web.md` | `upstream_ctf_skills`, `owasp_wstg`, `owasp_cheatsheets`, `owasp_top10`, `owasp_api_security`, `portswigger_wsa`, `sqlmap`, `tplmap`, `hacktricks`, `payloads_all_the_things` |
| rev | `docs/reference-digests/rev.md` | `upstream_ctf_skills`, `angr`, `angr_examples`, `radare2`, `ghidra` |
| crypto | `docs/reference-digests/crypto.md` | `upstream_ctf_skills`, `rsactftool`, `crypto_attacks`, `sage` |
| forensics | `docs/reference-digests/forensics.md` | `upstream_ctf_skills`, `volatility3`, `sleuthkit`, `binwalk` |
| stego | `docs/reference-digests/stego.md` | `upstream_ctf_skills`, `zsteg`, `binwalk`, `stegsolve_reference` |
| jail | `docs/reference-digests/jail.md` | `upstream_ctf_skills`, `tplmap`, `owasp_cheatsheets` |
| programming | `docs/reference-digests/programming.md` | `upstream_ctf_skills` |
| misc | `docs/reference-digests/misc.md` | `upstream_ctf_skills` |
| mobile | `docs/reference-digests/mobile.md` | `jadx`, `apktool`, `frida`, `mobsf`, `owasp_cheatsheets` |
| malware | `docs/reference-digests/malware.md` | `upstream_ctf_skills`, `capa`, `yara`, `ghidra`, `radare2`, `volatility3` |
| web3 | `docs/reference-digests/web3.md` | `foundry`, `slither`, `echidna`, `not_so_smart_contracts` |
| cloud/container | `docs/reference-digests/cloud-container.md` | `kctf`, `kubernetes_goat`, `trivy`, `hacktricks` |
| ai-ml | `docs/reference-digests/ai-ml.md` | `garak`, `damn_vulnerable_llm_agent`, `promptfoo`, `owasp_cheatsheets` |
| hardware-rf/side-channel | `docs/reference-digests/hardware-rf-side-channel.md` | `chipwhisperer`, `sigmf`, `urh` |
| osint | `docs/reference-digests/osint.md` | `sherlock`, `maigret` |
| hybrid | `docs/reference-digests/hybrid.md` | source and destination category digests |

## Operating Rule

Use the digest to form and rank hypotheses, then use
`tools/reference_query.py` against challenge evidence to open exact pinned
files under `.cache/references/`. Use local artifacts, transcripts, commands,
and replay evidence to validate claims. The reference cache is allowed; copying
or vendoring reference code into challenge work remains forbidden by default.
