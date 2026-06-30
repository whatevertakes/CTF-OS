# Hardware/RF And Side-Channel Reference Digest

## Trusted Sources

- `ref:chipwhisperer`: side-channel capture and analysis reference.
- `ref:sigmf`: signal metadata reference.
- `ref:urh`: RF decode workflow reference.

## CTF-Relevant Patterns

- Preserve raw captures and traces unchanged.
- Record sample rate, format, channel, modulation hints, hardware notes, firmware, timing logs, oracle behavior, sample count, and hashes.
- Decode modulation, framing, symbols, packets, and protocol fields with command provenance.
- For side channels, define leakage model, sample count, confidence, and independent verification before claiming secrets.

## CWE/CVE Mapping

- CVEs usually apply only to firmware, protocol stack, or device software versions evidenced in artifacts.
- Side-channel findings should be mapped to weakness patterns only after measurement evidence exists.

## Canonical Papers And Deep Dives

- Kocher timing attacks, power analysis, cache attacks, fault injection, and CPA/DPA literature are relevant when traces support the model.

## When To Use

- Use for RF captures, SDR traces, timing/power/cache/fault traces, hardware notes, firmware bridge artifacts, and repeated measurement oracles.

## When Not To Use

- Do not use when there is no raw measurement, capture metadata, or repeatable oracle.

## Source Anchors

- `idx:hardware-rf-side-channel:chipwhisperer:overview`
- `idx:hardware-rf-side-channel:sigmf:overview`
- `idx:hardware-rf-side-channel:urh:overview`
