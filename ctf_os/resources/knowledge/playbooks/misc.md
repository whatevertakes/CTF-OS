# Misc exploit-first playbook

## 1. Fast recon budget

Budget three observations: (1) challenge rule plus targeted file/protocol type; (2) one normal input/output; (3) one highest-value mechanism differential. Then select the solver, extraction, protocol exploit, or inversion path. Do not inventory every supplied detail.

## 2. Highest-value exploit hypotheses

Choose at most three concrete mechanisms supported by input: encoding/media transform, QR/barcode/OCR, signal/numeric inversion, graph/constraint solve, protocol state abuse, automation/race, or a narrowly evidenced ML behavior.

## 3. Cheapest decisive experiments

Decode one layer, render one channel/frame, solve a reduced constraint set, send one state-changing packet, or automate one representative interaction. The result must prove/kill the mechanism.

## 4. Immediate PoC criteria

A bounded script or direct command that reproduces the required transform, protocol action, solver output, or answer is a working PoC. Keep it challenge-specific and minimal.

## 5. Remote transition criteria

Move to the declared service when the state machine or solver is plausible; remote interaction may be the decisive experiment. Use branch-private services for crash/restart loops.

## 6. Kill conditions

Kill when a representative input disproves the mechanism, constraints do not reduce, or one changed experiment repeats the same failure. Replace the mechanism class, not just the tool.

## 7. Common research-drift traps

Do not broadly inventory files/protocols after a leading mechanism exists, build a generic automation framework, document every failed transform, switch tools without changing the hypothesis, or insist on an independent full rerun before remote.

## 8. Flag fast path

Publish the primitive or working solver first, execute it on the declared target or supplied input, preserve the minimal artifact/receipt, and surface the flag immediately.
