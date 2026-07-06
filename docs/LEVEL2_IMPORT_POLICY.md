# Level 2 Import Policy

This workspace does not vendor broad CTF repositories or install heavy tools by
default. External resources are references unless a specific challenge justifies
a narrow, reversible import. Broad tool installation is allowed only as an
explicit operator opt-in through `tools/install_advanced_ctf_tools.sh`; see
`docs/ADVANCED_CTF_TOOLING.md` for the patch/update contract and manual-tool
boundaries.

Curated references are tracked in `references.yaml`, resolved in
`references.lock.json`, and compressed into category digests under
`docs/reference-digests/`. Materialized references live under
`.cache/references/<repo>@<commit>` and are indexed under
`docs/reference-index/`. Level 3 workers should read the category digest and
query the local index, but they must still prove claims with challenge-local
evidence.

## Import Modes

| Mode | Rule |
|---|---|
| Reference only | Link, read, and summarize ideas. Do not copy code, challenges, or generated corpora into the workspace. |
| Optional tool | May be installed or cloned only for a specific challenge need, with the command and reason recorded in challenge notes. |
| Vendor | Avoid by default. Requires a narrow file set, license check, and explicit reason in the challenge evidence. |
| Local implementation | Prefer small stdlib scripts and challenge-local helpers over general frameworks. |

## Default Loading

External resources never load by default. A future agent should first inspect
local artifacts, then use references only when the category skill, category
digest, or evidence shows a concrete gap.

`tools/reference_refresh.py` validates the manifest, writes the lock file, and
materializes pinned references with `--materialize`, `--materialize-category`,
or `--materialize-all`. `tools/reference_index.py` builds local category
indexes. `tools/reference_query.py` performs evidence-gated lookup without
network access. `tools/reference_digest_check.py` verifies that installed CTF
skills, digests, and source anchors point to real local indexes.

## External Resource Evaluations

| Resource | Decision | Supports | Risk |
|---|---|---|---|
| `ljagiello/ctf-skills` ([github.com](https://github.com/ljagiello/ctf-skills)) | Reference only; copy style ideas, not bulk content. | Skill skeletons, category coverage. | MIT and active enough, but too large for default context. |
| `apsdehal/awesome-ctf` ([github.com](https://github.com/apsdehal/awesome-ctf)) | Reference only. | Tool discovery. | CC0, broad catalog, may be stale per item. |
| `zardus/ctf-tools` ([github.com](https://github.com/zardus/ctf-tools)) | Reference only. | Install catalog ideas. | BSD-3-Clause, broad installers are not suitable for a lean workspace. |
| `pwn.college` ([pwn.college](https://pwn.college/)) | Reference and benchmark only. | Core, pwn, reverse, and web training. | Educational-use rules; do not vendor challenges blindly. |
| `pwntools` ([github.com](https://github.com/Gallopsled/pwntools)) | Tool reference, optional future dependency. | Pwn. | Mature MIT CTF exploit framework; still not a default dependency. |
| `angr` ([github.com](https://github.com/angr/angr)) | MCP/tool reference. | Reverse engineering and symbolic execution. | BSD-2-Clause; configured MCP is already available. |
| `RsaCtfTool` ([github.com](https://github.com/RsaCtfTool/RsaCtfTool)) | Reference and optional tool. | Crypto. | MIT; Sage optional; use only when an RSA challenge demands it. |
| `Volatility3` ([github.com](https://github.com/volatilityfoundation/volatility3)) | Reference and optional tool. | Forensics and malware. | Custom VSL license; symbol/cache weight means no default load. |
| `kCTF` ([github.com](https://github.com/google/kctf)) / Kubernetes Goat ([github.com](https://github.com/madhuakula/kubernetes-goat)) | Reference only. | Cloud, container, and Kubernetes. | kCTF Apache-2.0, Goat MIT; local or owned infrastructure only. |
| Foundry ([github.com](https://github.com/foundry-rs/foundry)) / Echidna ([github.com](https://github.com/crytic/echidna)) | Reference and optional tools. | Blockchain and web3. | Foundry MIT/Apache; Echidna AGPL, avoid vendoring. |
| `garak` ([github.com](https://github.com/NVIDIA/garak)) / Damn Vulnerable LLM Agent ([github.com](https://github.com/WithSecureLabs/damn-vulnerable-llm-agent)) | Reference only. | AI/ML security. | Apache-2.0; may require model/API secrets, never default. |
| ChipWhisperer ([github.com](https://github.com/newaetech/chipwhisperer)) / SigMF ([github.com](https://github.com/sigmf/SigMF)) / URH ([github.com](https://github.com/jopohl/urh)) | Reference only. | Hardware, RF, and side-channel. | Hardware-heavy; URH is archived/GPL, do not vendor. |

See `docs/CATEGORY_REFERENCE_MAP.md` for the current category-to-digest map.

## Challenge-Local Exceptions

If a challenge needs an external tool, record this in `notes.md`:

- exact source URL and version or commit
- install or clone command
- why local evidence requires it
- output files produced
- cleanup notes if the tool creates caches or generated data

Reading `.cache/references/` for hypothesis support does not require a
challenge-local exception. Copying reference code, running third-party tooling,
or installing dependencies still requires the notes entry above.
