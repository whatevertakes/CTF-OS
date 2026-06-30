# Stego Reference Digest

## Trusted Sources

- `ref:upstream_ctf_skills`: stego-related forensics subskills.
- `ref:zsteg`: image channel extraction reference.
- `ref:binwalk`: appended data and embedded file reference.
- `ref:stegsolve_reference`: visual bit-plane workflow reference.

## CTF-Relevant Patterns

- Hash carriers and record dimensions, codec, metadata, chunks, channels, frame count, palette, and compression.
- Avoid blind bulk extraction until a hint or carrier property justifies it.
- Test metadata, appended data, archive signatures, bit planes, palette changes, audio channels, frame deltas, transforms, and encodings with provenance.
- Rehash recovered payloads and route conventional artifacts to forensics, crypto, rev, or misc.

## CWE/CVE Mapping

- CVEs usually do not drive stego solves except known parser/rendering vulnerabilities in supplied viewers or converters.

## Canonical Papers And Deep Dives

- LSB, palette, transform-domain, and format-chunk references are useful only when carrier properties support them.

## When To Use

- Use for hidden data in images, audio, video, documents, archives, and carrier files.

## When Not To Use

- Do not use after extraction yields a conventional archive, binary, ciphertext, or script.

## Source Anchors

- `idx:stego:upstream_ctf_skills:overview`
- `idx:stego:zsteg:overview`
- `idx:stego:binwalk:overview`
- `idx:stego:stegsolve_reference:overview`
