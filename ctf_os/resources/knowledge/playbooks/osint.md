# OSINT flag-first playbook

## 1. Fast recon budget

Use only public targets/artifacts named by the challenge. Budget three observations: (1) extract the highest-specificity clue; (2) make one high-value public query/pivot; (3) make one independent attribution check. Then choose the answer path.

## 2. Highest-value exploit hypotheses

Prefer a small number of provenance paths: domain/DNS/certificate, archived page, public Git/history, image/document metadata/OCR, video frame, or map/location clue. Treat each as a concrete attribution hypothesis with a kill condition.

## 3. Cheapest decisive experiments

Query the exact identifier, date/domain, archive snapshot, metadata field, distinctive visual clue, or commit fragment most likely to uniquely confirm the answer. Keep request volume small.

## 4. Immediate PoC criteria

A reproducible public URL/archive record or deterministic metadata/OCR extraction that uniquely supports the formatted answer is the OSINT working PoC. Preserve only the decisive capture and timestamp.

## 5. Remote transition criteria

Verify the candidate against the named public source or organizer-provided virtual account as soon as it is plausible. No personal login or unrelated-person correlation is allowed.

## 6. Kill conditions

Kill a pivot when the decisive source contradicts it, the clue is non-unique, or two bounded high-value queries add no attribution proximity. Switch source family, not to broad identity mapping.

## 7. Common research-drift traps

Do not build a comprehensive identity map, enumerate accounts, collect unrelated personal data, browse every archive date, document all clues, or require a universal independent verifier before surfacing a well-proven answer.

## 8. Flag fast path

Publish the decisive attribution pivot, verify the required flag formatting, preserve URL/timestamp/hash or extraction script, and surface the candidate. Human submission remains the competition oracle.
