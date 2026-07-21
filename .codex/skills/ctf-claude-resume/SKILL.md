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
5. Execute the cheapest decisive experiment in the rescue sandbox or current Sol sandbox. Run no more than the declared one to three experiments.
6. If the result works, integrate it only through the existing typed milestone and committed working-PoC paths.
7. For a remote flag claim, satisfy every existing `flag-receipt-save` requirement: current revision, exact command receipt, authorized remote observation, preserved output containing the candidate, and current-run exploit artifact.
8. Once the protected verified receipt exists, print the exact flag immediately for human submission. Do not submit it.
9. If an experiment hits its kill condition, record the actual `DECISIVE_EXPERIMENT` decision or `PRIMITIVE_REFUTED` milestone with evidence; do not preserve the claim as confirmed.
10. Continue the existing exploit-first Solve path when the rescue does not finish the challenge.
11. After adopting or refuting the rescue result, run `rescue-close` with `integrated`, `refuted`, `no-new-path`, or `manual` as appropriate.
12. Closing may remove only that rescue container and resource request. Preserve the rescue workspace and result.

Do not add rescue to race lineage, delegation plans, branch counts, candidates, milestones, or flag receipts merely because validation succeeded.
