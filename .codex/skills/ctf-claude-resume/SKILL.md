---
name: ctf-claude-resume
description: Validate a manual Claude rescue return as candidate insight and continue the exact CTF run to a verified remote flag. Use for “Claude 구조대 결과 이어서 풀어라”, “클로드 결과 검증해라”, “구조대 결과로 계속 풀어라”, or “Claude가 끝났으니 원격 플래그까지 해라”.
---

# Continue From Manual Claude Rescue

Validate the result without trusting it automatically, perform the cheapest decisive verification, and return control to the existing Solve path. Never submit a flag automatically.

## Workflow

1. Confirm the exact `run_id` and `rescue_attempt_id`. Never inspect another run or rescue attempt.
2. Run `rescue-return-validate` with the selector, contest, exact `--run-id`, and exact `--rescue-id`.
3. Read the generated `CODEX-RESUME.md`. Treat every Claude statement as candidate insight even after structural return validation.
4. Verify the first proposed command, artifact, evidence, success condition, and kill condition against the exact run and organizer-declared target.
5. Confirm every claimed observation refers to a canonical one-shot command receipt or `SESSION_OUTPUT_OBSERVED` receipt with exact run/rescue/packet/image identity. Execute the cheapest decisive experiment in the rescue sandbox or current Sol sandbox. Run no more than the declared one to three experiments.
6. If the result works, integrate it only through the existing typed milestone and committed working-PoC paths.
7. For a remote-ready return, verify that the artifact SHA-256 matches and the exact next argv executes that artifact (directly or as the interpreter's first script argument). Enforce the target index, success/kill conditions, and one-to-three experiment bound.
8. For a remote flag claim, use `rescue-flag-promote` with the exact run, rescue ID, canonical command/session observation receipt, candidate, and hashed exploit artifact. Do not ask the caller to restate host/port/protocol, output, network boolean, or arbitrary evidence path.
9. Once the protected verified receipt exists, print the exact flag immediately for human submission. Do not submit it.
10. If an experiment hits its kill condition, record the actual `DECISIVE_EXPERIMENT` decision or `PRIMITIVE_REFUTED` milestone with evidence; do not preserve the claim as confirmed.
11. Continue the existing exploit-first Solve path when the rescue does not finish the challenge.
12. Before close, explicitly close open persistent sessions. Run `rescue-close --outcome` with `integrated`, `refuted`, `no-new-path`, `flag-obtained`, or `manual`; `integrated`/`flag-obtained` must carry a milestone, working-PoC, protected flag, or validated execution observation receipt.
13. Closing may remove only that rescue container and resource request. Preserve the rescue workspace and result, including a rescue that failed before sandbox creation.

Do not add rescue to race lineage, delegation plans, branch counts, candidates, milestones, or flag receipts merely because validation succeeded.
