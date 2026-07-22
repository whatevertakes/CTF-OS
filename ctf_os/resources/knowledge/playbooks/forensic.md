# Forensic attack playbook

## 1. Fast recon budget

Hash the original, then budget three observations: (1) file/container type and size; (2) one structure/metadata listing targeted to the question; (3) one highest-value extraction/query. Then choose the shortest deterministic extraction path.

## 2. Highest-value exploit hypotheses

Select only evidence families tied to the question: a named filesystem object/deleted file, a focused memory process/secret, a PCAP stream, a firmware member, metadata/stego layer, or a specific media/OCR signal.

## 3. Cheapest decisive experiments

List one partition/directory/process/stream, carve one evidenced offset, filter one protocol/conversation, extract one metadata layer, or render one likely frame/channel. Avoid broad scans unless the artifact has no usable structure.

## 4. Immediate PoC criteria

A deterministic command or short script that extracts the answer/flag from the original hash is a working PoC. Once repeatable extraction exists, stop manual browsing.

## 5. Remote transition criteria

For remote acquisition/query tasks, switch as soon as the local filter/extractor is plausible. For static artifacts, deterministic extraction plus original fingerprint and provenance is the target transition.

## 6. Kill conditions

Kill an evidence family when the structure is absent, the targeted query returns no relevant object, or a bounded scan produces no question-linked proximity. Switch to a distinct artifact mechanism.

## 7. Common research-drift traps

Do not catalog every artifact, build a full timeline when a minimal timeline answers the question, carve everything by default, preserve decorative screenshots, or continue manual exploration after a deterministic script works.

## 8. Flag fast path

Publish deterministic extraction progress and the working script before narrative notes. Preserve original hash, exact command, extracted artifact/provenance, and surface the matching flag without demanding exhaustive cataloging.
