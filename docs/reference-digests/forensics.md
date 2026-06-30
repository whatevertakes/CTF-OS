# Forensics Reference Digest

## Trusted Sources

- `ref:upstream_ctf_skills`: forensics subskills for disk, memory, network, peripheral capture, and stego.
- `ref:volatility3`: memory forensics reference.
- `ref:sleuthkit`: disk/filesystem reference.
- `ref:binwalk`: firmware and embedded-file extraction reference.

## CTF-Relevant Patterns

- Hash and classify original artifacts before extraction or conversion.
- Preserve timestamps, timezone assumptions, packet counts, filesystem details, archive nesting, and tool versions.
- Preserve extracted files under `work/` with source offsets, commands, and hashes.
- Route recovered binaries, keys, ciphertext, scripts, or web traces only after boundary evidence exists.

## CWE/CVE Mapping

- CVEs are usually relevant only for known parser/file-format vulnerabilities or compromised software versions found in evidence.
- Avoid labeling artifacts as malicious or exploited without static, packet, memory, or timeline evidence.

## Canonical Papers And Deep Dives

- Volatility and SleuthKit documentation are primary workflow references.
- Network reassembly and memory acquisition literature is useful when metadata is complete.

## When To Use

- Use for disk images, memory dumps, pcaps, archives, logs, documents, firmware, and recovered payload chains.

## When Not To Use

- Do not use when the artifact has already reduced to a clean binary, source tree, or standalone crypto problem.

## Source Anchors

- `idx:forensics:upstream_ctf_skills:overview`
- `idx:forensics:volatility3:overview`
- `idx:forensics:sleuthkit:overview`
- `idx:forensics:binwalk:overview`
